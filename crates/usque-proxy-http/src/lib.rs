use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::info;

use usque_virtual_net::dns::DnsResolver;
use usque_virtual_net::VirtualStack;

pub struct HttpProxyConfig {
    pub bind: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
    pub resolver: DnsResolver,
}

pub async fn run(cfg: HttpProxyConfig, stack: Arc<VirtualStack>) -> Result<()> {
    let auth = match (&cfg.username, &cfg.password) {
        (Some(u), Some(p)) => Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{u}:{p}"),
        )),
        _ => None,
    };

    let listener = TcpListener::bind(cfg.bind).await?;
    info!("HTTP proxy listening on {}", cfg.bind);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let auth = auth.clone();
        let resolver = cfg.resolver.clone();
        let stack = Arc::clone(&stack);

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let auth = auth.clone();
                let resolver = resolver.clone();
                let stack = Arc::clone(&stack);
                async move { handle(req, auth, resolver, stack).await }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!("http proxy connection error: {err}");
            }
        });
    }
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    auth: Option<String>,
    resolver: DnsResolver,
    stack: Arc<VirtualStack>,
) -> Result<Response<http_body_util::Full<bytes::Bytes>>, hyper::Error> {
    if let Some(expected) = auth {
        let provided = req
            .headers()
            .get("proxy-authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != format!("Basic {expected}") {
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("Proxy-Authenticate", "Basic realm=\"Proxy\"")
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .unwrap());
        }
    }

    if req.method() == Method::CONNECT {
        return handle_connect(req, resolver, stack).await;
    }

    handle_http(req, resolver, stack).await
}

async fn handle_connect(
    req: Request<hyper::body::Incoming>,
    resolver: DnsResolver,
    stack: Arc<VirtualStack>,
) -> Result<Response<http_body_util::Full<bytes::Bytes>>, hyper::Error> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();

    let addr = resolve_connect_addr(&authority, &resolver).await;

    let mut dest = match stack.dial_tcp(addr).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::debug!("connect dial failed: {err}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .unwrap());
        }
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut dest).await;
            }
            Err(err) => tracing::debug!("upgrade failed: {err}"),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap())
}

async fn resolve_connect_addr(authority: &str, resolver: &DnsResolver) -> SocketAddr {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return addr;
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            if let Ok(ip) = resolver.lookup_ip(host).await {
                return SocketAddr::new(ip, port);
            }
        }
    }

    SocketAddr::from(([127, 0, 0, 1], 443))
}

async fn handle_http(
    req: Request<hyper::body::Incoming>,
    resolver: DnsResolver,
    stack: Arc<VirtualStack>,
) -> Result<Response<http_body_util::Full<bytes::Bytes>>, hyper::Error> {
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("localhost");
    let port = uri.port_u16().unwrap_or(80);
    let ip = resolver
        .lookup_ip(host)
        .await
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let addr = SocketAddr::new(ip, port);

    let mut stream = match stack.dial_tcp(addr).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::debug!("http dial failed: {err}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .unwrap());
        }
    };

    let request_line = format!("{} {} HTTP/1.1\r\n", req.method(), uri.path());
    use tokio::io::AsyncWriteExt;
    stream.write_all(request_line.as_bytes()).await.ok();
    for (name, value) in req.headers() {
        if name == "host" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            let _ = stream
                .write_all(format!("{name}: {v}\r\n").as_bytes())
                .await;
        }
    }
    stream.write_all(b"\r\n").await.ok();

    use tokio::io::AsyncReadExt;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(http_body_util::Full::new(bytes::Bytes::from(response)))
        .unwrap())
}
