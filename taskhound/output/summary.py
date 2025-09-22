from typing import List, Dict
from ..utils.logging import good

def print_summary_table(all_rows: List[Dict], backup_dir: str = None, has_hv_data: bool = False):
    """
    Print a nicely formatted summary table showing task counts per host
    """
    if not all_rows:
        return
    
    # Aggregate data by host
    host_stats = {}
    for row in all_rows:
        host = row.get("host", "Unknown")
        task_type = row.get("type", "TASK")
        
        if host not in host_stats:
            host_stats[host] = {"privileged": 0, "normal": 0}
        
        if task_type == "PRIV":
            host_stats[host]["privileged"] += 1
        else:
            host_stats[host]["normal"] += 1
    
    if not host_stats:
        return
    
    # Calculate column widths
    max_hostname_width = max(len("HOSTNAME"), max(len(host) for host in host_stats.keys()))
    priv_width = len("PRIVILEGED_TASKS")
    normal_width = len("NORMAL_TASKS")
    
    # Print header
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    # Print table header
    header = f"{'HOSTNAME':<{max_hostname_width}} | {'PRIVILEGED_TASKS':<{priv_width}} | {'NORMAL_TASKS':<{normal_width}}"
    print(header)
    print("-" * len(header))
    
    # Print rows
    total_priv = 0
    total_normal = 0
    for host in sorted(host_stats.keys()):
        priv_count = host_stats[host]["privileged"]
        normal_count = host_stats[host]["normal"]
        total_priv += priv_count
        total_normal += normal_count
        
        # Show N/A for privileged tasks if no high-value data was loaded
        priv_display = str(priv_count) if has_hv_data else "N/A"
        
        row = f"{host:<{max_hostname_width}} | {priv_display:<{priv_width}} | {normal_count:<{normal_width}}"
        print(row)
    
    # Print totals
    if len(host_stats) > 1:
        print("-" * len(header))
        total_priv_display = str(total_priv) if has_hv_data else "N/A"
        total_row = f"{'TOTAL':<{max_hostname_width}} | {total_priv_display:<{priv_width}} | {total_normal:<{normal_width}}"
        print(total_row)
    
    print("="*60)
    
    # Print additional info hint
    if not has_hv_data:
        good("NOTE: Privileged task detection requires --bh-data parameter")
        good("Without high-value target data, privileged tasks are marked as N/A")
    
    if backup_dir:
        good(f"Raw XML files saved to: {backup_dir}")
        good("Check the backup directory for detailed task information")
    else:
        good("Check the output above or your saved files for detailed task information")
    
    print()