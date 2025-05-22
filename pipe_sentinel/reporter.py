"""
Güvenlik raporlama sistemi
"""

import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .analyzer import SecurityRisk

class SecurityReporter:
    """Güvenlik raporlama sınıfı"""
    
    def __init__(self, output_dir: Path = Path("reports")):
        self.output_dir = output_dir
        self.console = Console()
        self.output_dir.mkdir(exist_ok=True)
        
    def _create_json_report(self, risks: List[SecurityRisk], workflow_path: Path) -> Dict:
        """JSON formatında rapor oluştur"""
        return {
            "report_date": datetime.now().isoformat(),
            "workflow_file": str(workflow_path),
            "total_risks": len(risks),
            "risk_levels": {
                "CRITICAL": len([r for r in risks if r.severity == "CRITICAL"]),
                "HIGH": len([r for r in risks if r.severity == "HIGH"]),
                "MEDIUM": len([r for r in risks if r.severity == "MEDIUM"]),
                "LOW": len([r for r in risks if r.severity == "LOW"])
            },
            "risks": [risk.dict() for risk in risks]
        }
        
    def _save_json_report(self, report: Dict, workflow_path: Path):
        """JSON raporunu dosyaya kaydet"""
        report_file = self.output_dir / f"{workflow_path.stem}_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return report_file
        
    def _create_console_table(self, risks: List[SecurityRisk]) -> Table:
        """Konsol için tablo oluştur"""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Risk", style="dim")
        table.add_column("Severity", style="red")
        table.add_column("Line", justify="right")
        table.add_column("CVE", style="blue")
        table.add_column("Fix", style="green")
        
        for risk in risks:
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "orange3",
                "MEDIUM": "yellow",
                "LOW": "green"
            }.get(risk.severity, "white")
            
            table.add_row(
                risk.risk,
                f"[{severity_color}]{risk.severity}[/{severity_color}]",
                str(risk.line),
                risk.cve or "N/A",
                risk.fix or "N/A"
            )
            
        return table
        
    def generate_report(self, risks: List[SecurityRisk], workflow_path: Path, detailed: bool = False):
        """Güvenlik raporu oluştur"""
        # JSON raporu oluştur ve kaydet
        json_report = self._create_json_report(risks, workflow_path)
        report_file = self._save_json_report(json_report, workflow_path)
        
        # Konsol çıktısı
        self.console.print(Panel.fit(
            f"[bold green]PipeSentinel Güvenlik Raporu[/bold green]\n"
            f"Dosya: {workflow_path}\n"
            f"Toplam Risk: {len(risks)}\n"
            f"Rapor: {report_file}",
            title="Rapor Oluşturuldu",
            border_style="green"
        ))
        
        # Risk özeti
        self.console.print("\n[bold]Risk Özeti:[/bold]")
        for severity, count in json_report["risk_levels"].items():
            if count > 0:
                self.console.print(f"- {severity}: {count}")
                
        # Detaylı rapor
        if detailed:
            self.console.print("\n[bold]Detaylı Risk Listesi:[/bold]")
            self.console.print(self._create_console_table(risks))
            
            # Her risk için detaylı açıklama
            for risk in risks:
                self.console.print(Panel(
                    f"[bold]{risk.risk}[/bold]\n"
                    f"Severity: {risk.severity}\n"
                    f"Line: {risk.line}\n"
                    f"CVE: {risk.cve or 'N/A'}\n"
                    f"Fix: {risk.fix or 'N/A'}\n"
                    f"Description: {risk.description or 'N/A'}",
                    title=f"Risk Detayı - {risk.cve or 'N/A'}",
                    border_style="yellow"
                )) 