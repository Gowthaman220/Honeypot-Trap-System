import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.ip_stat import IPStatistic
from app.models.event import Event


class IPTracker:
    """Updates and aggregates threat intelligence profiles for source IPs."""

    @staticmethod
    def update_ip_stat(event: Event, db: Session) -> IPStatistic:
        ip_stat = db.query(IPStatistic).filter(IPStatistic.source_ip == event.source_ip).first()
        now = datetime.now(timezone.utc)

        if not ip_stat:
            services = [event.service]
            ip_stat = IPStatistic(
                source_ip=event.source_ip,
                total_events=1,
                first_seen=now,
                last_seen=now,
                highest_risk_score=event.risk_score,
                services_targeted=json.dumps(services),
                threat_level=event.severity
            )
            db.add(ip_stat)
        else:
            ip_stat.total_events += 1
            ip_stat.last_seen = now
            if event.risk_score > ip_stat.highest_risk_score:
                ip_stat.highest_risk_score = event.risk_score
                ip_stat.threat_level = event.severity

            # Update targeted services list
            try:
                services = json.loads(ip_stat.services_targeted)
            except Exception:
                services = []
            if event.service not in services:
                services.append(event.service)
                ip_stat.services_targeted = json.dumps(services)

        db.commit()
        db.refresh(ip_stat)
        return ip_stat


ip_tracker = IPTracker()
