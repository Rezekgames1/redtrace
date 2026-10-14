use redtrace::{
    agent::{Delivery, deliver_chunk, parse_server},
    ingest::{AgentRegistry, IngestState, IngestStats, ingest_router},
    model::Event,
    storage::Wal,
};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};
use tokio::sync::{RwLock, mpsc};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_checks_server_identity_and_delivers_durable_events() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = certificate.cert.pem();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem(
        pem.as_bytes().to_vec(),
        certificate.signing_key.serialize_pem().as_bytes().to_vec(),
    )
    .await
    .unwrap();
    let dir = std::env::temp_dir().join(format!(
        "redtrace-tls-{}",
        redtrace::ingest::hex(&redtrace::ingest::sha256(pem.as_bytes()))
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, pem).unwrap();
    let registry = Arc::new(AgentRegistry::open(dir.join("agents.json")).unwrap());
    let (_, token) = registry.create("tls-test").unwrap();
    let (tx, mut rx) = mpsc::channel::<Event>(16);
    let known = Arc::new(RwLock::new(HashSet::new()));
    let state = IngestState {
        registry,
        events: tx,
        known_uids: known.clone(),
        stats: Arc::new(RwLock::new(IngestStats::default())),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(
        axum_server::from_tcp_rustls(listener, config)
            .unwrap()
            .serve(ingest_router(state).into_make_service()),
    );
    let wal = Wal::open(dir.join("events.wal")).unwrap();
    let writer = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            wal.append(std::slice::from_ref(&event)).unwrap();
            known.write().await.insert(event.uid);
        }
    });
    let url = format!("https://localhost:{port}");
    let passed = tokio::task::spawn_blocking(move || {
        let event = Event::normalized(
            0,
            "2026-10-07T00:00:00Z".into(),
            "windows.system".into(),
            "low".into(),
            "TLS test".into(),
            BTreeMap::new(),
        );
        let mut endpoint = parse_server(&url).unwrap();
        endpoint.ca_file = None;
        assert!(matches!(
            deliver_chunk(&endpoint, &token, "tls-test", std::slice::from_ref(&event)),
            Delivery::Unreachable { .. }
        ));
        endpoint.ca_file = Some(ca.clone());
        assert_eq!(
            deliver_chunk(&endpoint, &token, "tls-test", std::slice::from_ref(&event)),
            Delivery::Accepted {
                accepted: 1,
                duplicates: 0
            }
        );
        let mut wrong_host = parse_server(&format!("https://127.0.0.1:{port}")).unwrap();
        wrong_host.ca_file = Some(ca);
        assert!(matches!(
            deliver_chunk(&wrong_host, &token, "tls-test", &[event]),
            Delivery::Unreachable { .. }
        ));
    })
    .await;
    server.abort();
    writer.abort();
    let _ = server.await;
    let _ = writer.await;
    std::fs::remove_dir_all(dir).unwrap();
    passed.unwrap();
}
