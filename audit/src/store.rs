use crate::{AuditEvent, AuditQuery, AuditTrail};

pub struct AuditStore {
    events: Vec<AuditEvent>,
}

impl AuditStore {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn append(&mut self, event: AuditEvent) {
        self.events.push(event);
    }

    pub fn append_batch(&mut self, events: Vec<AuditEvent>) {
        self.events.extend(events);
    }

    pub fn query(&self, filter: &AuditQuery) -> AuditTrail {
        let mut filtered: Vec<&AuditEvent> = self.events.iter().collect();

        if let Some(ref tenant_id) = filter.tenant_id {
            filtered.retain(|e| &e.tenant_id == tenant_id);
        }
        if let Some(ref category) = filter.category {
            filtered.retain(|e| &e.category == category);
        }
        if let Some(ref severity) = filter.severity {
            filtered.retain(|e| &e.severity == severity);
        }
        if let Some(ref actor) = filter.actor {
            filtered.retain(|e| &e.actor == actor);
        }
        if let Some(ref resource_type) = filter.resource_type {
            filtered.retain(|e| &e.resource_type == resource_type);
        }
        if let Some(start) = filter.start_time {
            filtered.retain(|e| e.timestamp >= start);
        }
        if let Some(end) = filter.end_time {
            filtered.retain(|e| e.timestamp <= end);
        }

        let total_count = filtered.len();
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(100);

        let events: Vec<AuditEvent> = filtered
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();

        let has_more = offset + limit < total_count;

        AuditTrail {
            events,
            total_count,
            has_more,
        }
    }

    pub fn count(&self) -> usize {
        self.events.len()
    }

    pub fn count_for_tenant(&self, tenant_id: &str) -> usize {
        self.events
            .iter()
            .filter(|e| e.tenant_id == tenant_id)
            .count()
    }

    pub fn recent_events(&self, limit: usize) -> Vec<&AuditEvent> {
        self.events.iter().rev().take(limit).collect()
    }
}

impl Default for AuditStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditCategory, AuditSeverity};

    #[test]
    fn test_store_append_and_query() {
        let mut store = AuditStore::new();
        store.append(AuditEvent::new(
            "t1",
            AuditCategory::Authentication,
            AuditSeverity::Info,
            "user1",
            "login",
            "session",
            "s1",
        ));
        store.append(AuditEvent::new(
            "t2",
            AuditCategory::DataAccess,
            AuditSeverity::Info,
            "user2",
            "read",
            "doc",
            "d1",
        ));

        let filter = AuditQuery {
            tenant_id: Some("t1".into()),
            category: None,
            severity: None,
            actor: None,
            resource_type: None,
            start_time: None,
            end_time: None,
            limit: None,
            offset: None,
        };

        let trail = store.query(&filter);
        assert_eq!(trail.total_count, 1);
        assert_eq!(trail.events[0].tenant_id, "t1");
    }

    #[test]
    fn test_store_count() {
        let mut store = AuditStore::new();
        store.append(AuditEvent::new(
            "t1",
            AuditCategory::Authentication,
            AuditSeverity::Info,
            "user1",
            "login",
            "session",
            "s1",
        ));
        assert_eq!(store.count(), 1);
    }
}
