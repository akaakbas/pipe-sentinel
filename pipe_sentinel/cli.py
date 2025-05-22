"""
PipeSentinel CLI modülü
"""

import typer
from rich.console import Console
from rich.panel import Panel
from pathlib import Path
from .analyzer import WorkflowAnalyzer
from .reporter import SecurityReporter
from .simulator import PipelineSimulator

app = typer.Typer(
    name="pipe_sentinel",
    help="CI/CD Pipeline Güvenlik Denetleyicisi",
    add_completion=False
)
console = Console()

@app.command()
def analyze(
    workflow_file: Path = typer.Argument(
        ...,
        help="Analiz edilecek workflow dosyasının yolu",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    detailed: bool = typer.Option(
        False,
        "--detailed",
        "-d",
        help="Detaylı analiz raporu oluştur",
    ),
    scenario: str = typer.Option(
        None,
        "--scenario",
        "-s",
        help="Belirli bir saldırı senaryosu uygula",
    ),
    simulate: bool = typer.Option(
        False,
        "--simulate",
        help="Docker ortamında simülasyon yap",
    ),
):
    """
    CI/CD workflow dosyasını analiz et ve güvenlik açıklarını tespit et.
    """
    console.print(Panel.fit(
        "[bold green]PipeSentinel[/bold green] - CI/CD Pipeline Güvenlik Denetleyicisi",
        title="Başlatılıyor",
        border_style="green"
    ))
    
    try:
        # Workflow analizi
        analyzer = WorkflowAnalyzer(workflow_file)
        risks = analyzer.analyze()
        
        # Raporlama
        reporter = SecurityReporter()
        reporter.generate_report(risks, workflow_file, detailed)
        
        # Simülasyon
        if simulate:
            console.print("\n[bold]Pipeline Simülasyonu Başlatılıyor...[/bold]")
            simulator = PipelineSimulator()
            try:
                with open(workflow_file, 'r', encoding='utf-8') as f:
                    workflow_content = f.read()
                
                result = simulator.simulate(workflow_content)
                console.print(Panel(
                    f"Simülasyon Sonucu:\n"
                    f"Status: {result['status']}\n"
                    f"Exit Code: {result['exit_code']}\n"
                    f"Output: {result['output']}",
                    title="Simülasyon Tamamlandı",
                    border_style="blue"
                ))
            finally:
                simulator.cleanup()
                
    except Exception as e:
        console.print(Panel(
            f"[bold red]Hata:[/bold red] {str(e)}",
            title="Analiz Başarısız",
            border_style="red"
        ))
        raise typer.Exit(1)

def main():
    app() 