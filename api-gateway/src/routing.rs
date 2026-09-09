use crate::{ApiRoute, BackendService};

pub struct Router {
    routes: Vec<ApiRoute>,
    services: Vec<BackendService>,
}

impl Router {
    pub fn new(routes: Vec<ApiRoute>, services: Vec<BackendService>) -> Self {
        Self { routes, services }
    }

    pub fn resolve(&self, path: &str, method: &str) -> Option<&ApiRoute> {
        self.routes.iter().find(|r| {
            let path_match = r.path == "*" || path.starts_with(&r.path);
            let method_match = r.method == "*" || r.method.eq_ignore_ascii_case(method);
            path_match && method_match
        })
    }

    pub fn backend_for_route(&self, route: &ApiRoute) -> Option<&BackendService> {
        self.services.iter().find(|s| s.name == route.backend)
    }

    pub fn list_routes(&self) -> &[ApiRoute] {
        &self.routes
    }

    pub fn list_services(&self) -> &[BackendService] {
        &self.services
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_resolve() {
        let routes = vec![
            ApiRoute {
                path: "/api/v1/auth".into(),
                method: "POST".into(),
                backend: "auth".into(),
                auth_required: false,
                rate_limit: None,
                timeout_ms: None,
            },
            ApiRoute {
                path: "/api/v1/governance".into(),
                method: "*".into(),
                backend: "governance".into(),
                auth_required: true,
                rate_limit: None,
                timeout_ms: None,
            },
        ];

        let router = Router::new(routes, vec![]);
        assert!(router.resolve("/api/v1/auth", "POST").is_some());
        assert!(router.resolve("/api/v1/auth", "GET").is_none());
        assert!(router.resolve("/api/v1/governance", "DELETE").is_some());
    }
}
