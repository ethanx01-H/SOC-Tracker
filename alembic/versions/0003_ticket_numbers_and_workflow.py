"""Use sequential ticket labels and the Open/Pending/WIP/Closed workflow."""

from alembic import op


revision = "0003_ticket_numbers_and_workflow"
down_revision = "0002_add_evidence_audit"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    connection.exec_driver_sql(
        """
        UPDATE fastapi_audit_logs
        SET target_id = '#' || (
            SELECT id FROM fastapi_alerts WHERE fastapi_alerts.alert_id = fastapi_audit_logs.target_id
        )
        WHERE target_type = 'alert'
          AND EXISTS (
            SELECT 1 FROM fastapi_alerts WHERE fastapi_alerts.alert_id = fastapi_audit_logs.target_id
          )
        """
    )
    connection.exec_driver_sql("UPDATE fastapi_alerts SET alert_id = '#' || id")
    connection.exec_driver_sql(
        """
        UPDATE fastapi_alerts
        SET status = CASE
            WHEN status = 'Closed' THEN 'Closed'
            WHEN status IN ('Investigating', 'Escalated', 'Contained') THEN 'WIP'
            WHEN assigned_to_id IS NOT NULL OR analyst <> 'Unassigned' THEN 'Pending'
            ELSE 'Open'
        END
        """
    )


def downgrade():
    connection = op.get_bind()
    connection.exec_driver_sql("UPDATE fastapi_alerts SET alert_id = 'SOC-' || printf('%06d', id)")
    connection.exec_driver_sql(
        """
        UPDATE fastapi_alerts
        SET status = CASE
            WHEN status = 'Closed' THEN 'Closed'
            WHEN status = 'WIP' THEN 'Investigating'
            WHEN status = 'Pending' THEN 'Triage'
            ELSE 'New'
        END
        """
    )
