from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
import json, os

DEFAULT_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_results", "reports")

def export_html(json_path, output_html_path, template_dir=None):
    if template_dir is None:
        template_dir = DEFAULT_TEMPLATE_DIR
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html.j2")
    rendered = template.render(data=data)
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    return output_html_path

def export_pdf(html_path, output_pdf_path):
    with open(html_path, "rb") as source_html:
        with open(output_pdf_path, "wb") as result_file:
            pisa_status = pisa.CreatePDF(source_html, dest=result_file)
    return output_pdf_path

def export_report(json_path, output_dir=None):
    if output_dir is None:
        output_dir = DEFAULT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(json_path))[0]
    html_path = export_html(json_path, os.path.join(output_dir, f"{base}.html"))
    pdf_path = export_pdf(html_path, os.path.join(output_dir, f"{base}.pdf"))
    return html_path, pdf_path
