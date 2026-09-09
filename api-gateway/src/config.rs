use crate::{ApiRoute, BackendService};

pub fn default_routes() -> Vec<ApiRoute> {
    vec![
        ApiRoute {
            path: "/api/v1/auth".into(),
            method: "POST".into(),
            backend: "sovereign-identity".into(),
            auth_required: false,
            rate_limit: Some(10),
            timeout_ms: Some(5000),
        },
        ApiRoute {
            path: "/api/v1/governance".into(),
            method: "GET".into(),
            backend: "governance-workflow".into(),
            auth_required: true,
            rate_limit: Some(100),
            timeout_ms: Some(10000),
        },
        ApiRoute {
            path: "/api/v1/compliance".into(),
            method: "GET".into(),
            backend: "compliance-as-code".into(),
            auth_required: true,
            rate_limit: Some(100),
            timeout_ms: Some(10000),
        },
        ApiRoute {
            path: "/api/v1/risk".into(),
            method: "GET".into(),
            backend: "risk-intelligence".into(),
            auth_required: true,
            rate_limit: Some(100),
            timeout_ms: Some(10000),
        },
        ApiRoute {
            path: "/api/v1/audit".into(),
            method: "GET".into(),
            backend: "audit-ledger".into(),
            auth_required: true,
            rate_limit: Some(50),
            timeout_ms: Some(10000),
        },
        ApiRoute {
            path: "/api/v1/metrics".into(),
            method: "GET".into(),
            backend: "trust-score-engine".into(),
            auth_required: true,
            rate_limit: Some(50),
            timeout_ms: Some(5000),
        },
    ]
}

pub fn default_services() -> Vec<BackendService> {
    vec![
        BackendService {
            name: "sovereign-identity".into(),
            url: std::env::var("SOVEREIGN_IDENTITY_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8081".into()),
            health_path: "/health".into(),
            timeout_ms: 5000,
            retry_count: 3,
        },
        BackendService {
            name: "compliance-as-code".into(),
            url: std::env::var("COMPLIANCE_AS_CODE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8082".into()),
            health_path: "/health".into(),
            timeout_ms: 10000,
            retry_count: 3,
        },
        BackendService {
            name: "trust-score-engine".into(),
            url: std::env::var("TRUST_SCORE_ENGINE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8083".into()),
            health_path: "/health".into(),
            timeout_ms: 5000,
            retry_count: 3,
        },
        BackendService {
            name: "risk-intelligence".into(),
            url: std::env::var("RISK_INTELLIGENCE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8084".into()),
            health_path: "/health".into(),
            timeout_ms: 10000,
            retry_count: 3,
        },
        BackendService {
            name: "audit-ledger".into(),
            url: std::env::var("AUDIT_LEDGER_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8085".into()),
            health_path: "/health".into(),
            timeout_ms: 10000,
            retry_count: 3,
        },
        BackendService {
            name: "governance-workflow".into(),
            url: std::env::var("GOVERNANCE_WORKFLOW_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8086".into()),
            health_path: "/health".into(),
            timeout_ms: 10000,
            retry_count: 3,
        },
    ]
}

pub fn find_service<'a>(services: &'a [BackendService], name: &str) -> Option<&'a BackendService> {
    services.iter().find(|s| s.name == name)
}

pub fn find_route<'a>(routes: &'a [ApiRoute], path: &str, method: &str) -> Option<&'a ApiRoute> {
    routes
        .iter()
        .find(|r| r.path == path && (r.method == "*" || r.method == method))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_routes() {
        let routes = default_routes();
        assert!(!routes.is_empty());
        assert!(routes.iter().any(|r| r.path == "/api/v1/auth"));
    }

    #[test]
    fn test_default_services() {
        let services = default_services();
        assert!(!services.is_empty());
        assert!(services.iter().any(|s| s.name == "sovereign-identity"));
    }
}
