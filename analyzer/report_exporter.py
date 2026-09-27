from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
import json, os

def export_html(json_path, output_html_path, template_dir="analyzer/templates"):
    with open(json_path) as f:
        data = json.load(f)
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html.j2")
    rendered = template.render(data=data)
    with open(output_html_path, "w") as f:
        f.write(rendered)
    return output_html_path

def export_pdf(html_path, output_pdf_path):
    with open(html_path, "r") as source_html:
        with open(output_pdf_path, "wb") as result_file:
            pisa_status = pisa.CreatePDF(source_html, dest=result_file)
    return output_pdf_path

def export_report(json_path, output_dir="sample_results/reports"):
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(json_path))[0]
    html_path = export_html(json_path, f"{output_dir}/{base}.html")
    pdf_path = export_pdf(html_path, f"{output_dir}/{base}.pdf")
    return html_path, pdf_path
