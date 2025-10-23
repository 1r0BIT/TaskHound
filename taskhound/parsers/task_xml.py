# Parse a Scheduled Task XML blob and extract a small set of fields.
#
# The function is intentionally forgiving: malformed XML or missing
# elements result in None values rather than exceptions. Only the fields
# we care about for privilege analysis are extracted.
# Can be extended later if needed.

import xml.etree.ElementTree as ET
from typing import Dict


def parse_task_xml(xml_bytes: bytes) -> Dict[str, str]:
    res = {"runas": None, "author": None, "date": None, "command": None, "arguments": None, "logon_type": None, "enabled": None,
           "trigger_type": None, "start_boundary": None, "interval": None, "duration": None, "days_interval": None}
    try:
        root = ET.fromstring(xml_bytes)
        # Handle default namespace if present by binding it to prefix 'ns'
        # Task Scheduler XML typically uses http://schemas.microsoft.com/windows/2004/02/mit/task
        ns = {}
        if root.tag.startswith('{'):
            namespace_uri = root.tag.split('}')[0].strip('{')
            ns = {"ns": namespace_uri}

        def grab(path):
            # Try with namespace first, then without
            node = root.find(path, ns) if ns else None
            if node is None:
                # Fallback: try without namespace
                fallback_path = path.replace('ns:', '')
                node = root.find(fallback_path)
            return node.text.strip() if (node is not None and node.text) else None

        # Principal/UserId holds the account the task runs as
        res["runas"]     = grab(".//ns:Principal/ns:UserId")
        res["author"]    = grab(".//ns:RegistrationInfo/ns:Author")
        res["date"]      = grab(".//ns:RegistrationInfo/ns:Date")
        # Command and Arguments can be nested under different nodes in some schemas;
        # this covers the common Task Scheduler schema used by Windows.
        res["command"]   = grab(".//ns:Command")
        res["arguments"] = grab(".//ns:Arguments")
        # LogonType indicates whether credentials are stored (Password) or if S4U/token is used
        res["logon_type"] = grab(".//ns:Principal/ns:LogonType")

        # Task state information - critical for identifying disabled tasks that may still store credentials
        res["enabled"]   = grab(".//ns:Settings/ns:Enabled")

        # Parse trigger information for schedule analysis
        # Try to find the first trigger and determine its type and schedule
        triggers_node = root.find(".//ns:Triggers", ns) if ns else root.find(".//Triggers")
        if triggers_node is not None:
            # Check for different trigger types in order of preference (CalendarTrigger is most detailed)
            calendar_trigger = triggers_node.find("ns:CalendarTrigger", ns) if ns else triggers_node.find("CalendarTrigger")
            time_trigger = triggers_node.find("ns:TimeTrigger", ns) if ns else triggers_node.find("TimeTrigger")
            logon_trigger = triggers_node.find("ns:LogonTrigger", ns) if ns else triggers_node.find("LogonTrigger")
            boot_trigger = triggers_node.find("ns:BootTrigger", ns) if ns else triggers_node.find("BootTrigger")
            idle_trigger = triggers_node.find("ns:IdleTrigger", ns) if ns else triggers_node.find("IdleTrigger")
            event_trigger = triggers_node.find("ns:EventTrigger", ns) if ns else triggers_node.find("EventTrigger")

            if calendar_trigger is not None:
                res["trigger_type"] = "Calendar"
                # Extract start boundary
                start_boundary_node = calendar_trigger.find("ns:StartBoundary", ns) if ns else calendar_trigger.find("StartBoundary")
                if start_boundary_node is not None and start_boundary_node.text:
                    res["start_boundary"] = start_boundary_node.text.strip()

                # Extract repetition information
                repetition_node = calendar_trigger.find("ns:Repetition", ns) if ns else calendar_trigger.find("Repetition")
                if repetition_node is not None:
                    interval_node = repetition_node.find("ns:Interval", ns) if ns else repetition_node.find("Interval")
                    duration_node = repetition_node.find("ns:Duration", ns) if ns else repetition_node.find("Duration")
                    if interval_node is not None and interval_node.text:
                        res["interval"] = interval_node.text.strip()
                    if duration_node is not None and duration_node.text:
                        res["duration"] = duration_node.text.strip()

                # Extract schedule by day information
                schedule_by_day_node = calendar_trigger.find("ns:ScheduleByDay", ns) if ns else calendar_trigger.find("ScheduleByDay")
                if schedule_by_day_node is not None:
                    days_interval_node = schedule_by_day_node.find("ns:DaysInterval", ns) if ns else schedule_by_day_node.find("DaysInterval")
                    if days_interval_node is not None and days_interval_node.text:
                        res["days_interval"] = days_interval_node.text.strip()

            elif time_trigger is not None:
                res["trigger_type"] = "Time"
                start_boundary_node = time_trigger.find("ns:StartBoundary", ns) if ns else time_trigger.find("StartBoundary")
                if start_boundary_node is not None and start_boundary_node.text:
                    res["start_boundary"] = start_boundary_node.text.strip()

            elif logon_trigger is not None:
                res["trigger_type"] = "Logon"

            elif boot_trigger is not None:
                res["trigger_type"] = "Boot"

            elif idle_trigger is not None:
                res["trigger_type"] = "Idle"

            elif event_trigger is not None:
                res["trigger_type"] = "Event"

    except Exception:
        # Be permissive: return default dict with None values on parse errors
        pass
    return res
