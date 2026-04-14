#!/usr/bin/env python3
"""
Beautiful PDF Generator for ASTRA Reports
Implements modern design principles and professional styling.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch, cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Frame, PageTemplate, Image, KeepTogether
)
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF
from datetime import datetime
from pathlib import Path
import json


# Professional Color Palette (inspired by modern security dashboards)
class Colors:
    """Professional color scheme for security reports"""
    # Brand colors
    PRIMARY = colors.HexColor('#1a237e')      # Deep indigo
    SECONDARY = colors.HexColor('#0d47a1')    # Blue
    ACCENT = colors.HexColor('#00bcd4')       # Cyan
    
    # Risk colors (more sophisticated than basic red/yellow/green)
    CRITICAL = colors.HexColor('#d32f2f')     # Red
    HIGH = colors.HexColor('#f57c00')         # Orange
    MODERATE = colors.HexColor('#fbc02d')     # Amber
    LOW = colors.HexColor('#7cb342')          # Light green
    MINIMAL = colors.HexColor('#388e3c')      # Green
    
    # UI colors
    BACKGROUND = colors.HexColor('#f5f5f5')   # Light grey
    SURFACE = colors.white
    TEXT_PRIMARY = colors.HexColor('#212121') # Almost black
    TEXT_SECONDARY = colors.HexColor('#757575') # Grey
    DIVIDER = colors.HexColor('#bdbdbd')      # Light grey
    
    # Gradient-like colors for charts
    GRADIENT_START = colors.HexColor('#1976d2')
    GRADIENT_MID = colors.HexColor('#42a5f5')
    GRADIENT_END = colors.HexColor('#90caf9')
    
    # Table alternating rows
    TABLE_HEADER = colors.HexColor('#263238')  # Dark blue-grey
    TABLE_ROW_EVEN = colors.HexColor('#eceff1') # Very light blue-grey
    TABLE_ROW_ODD = colors.white


class BeautifulPDFGenerator:
    """Modern, beautiful PDF generator for ASTRA reports."""
    
    def __init__(self, config):
        self.config = config
        self.colors = Colors()
        
    def generate(self, json_file: str) -> str:
        """Generate a beautiful PDF report from JSON data."""
        # Load JSON data
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Create output directory
        output_path = Path(self.config.get('output.pdf_path', './reports'))
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate PDF filename
        report_id = data['metadata']['report_id']
        pdf_file = output_path / f"{report_id}.pdf"
        
        # Create document with custom page template
        doc = SimpleDocTemplate(
            str(pdf_file),
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=3*cm,
            bottomMargin=2.5*cm,
            title=f"ASTRA Risk Assessment - {report_id}",
            author="ASTRA Security Assessment Tool"
        )
        
        # Build the story (content)
        story = []
        styles = self._create_custom_styles()
        
        # Add pages
        self._add_cover_page(story, data, styles)
        self._add_executive_summary(story, data, styles)
        self._add_risk_breakdown(story, data, styles)
        self._add_vulnerability_analysis(story, data, styles)
        self._add_remediation_priorities(story, data, styles)
        self._add_entity_details(story, data, styles)
        self._add_methodology_page(story, data, styles)
        
        # Build PDF with custom page templates
        doc.build(
            story,
            onFirstPage=lambda canvas, doc: self._add_first_page_decoration(canvas, doc, data),
            onLaterPages=lambda canvas, doc: self._add_page_decoration(canvas, doc, data)
        )
        
        return str(pdf_file)
    
    def _create_custom_styles(self):
        """Create custom paragraph styles with modern typography."""
        styles = getSampleStyleSheet()
        
        # Cover page title
        styles.add(ParagraphStyle(
            name='CoverTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=36,
            leading=42,
            textColor=self.colors.PRIMARY,
            alignment=TA_CENTER,
            spaceAfter=20
        ))
        
        # Cover subtitle
        styles.add(ParagraphStyle(
            name='CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=16,
            leading=20,
            textColor=self.colors.TEXT_SECONDARY,
            alignment=TA_CENTER,
            spaceAfter=10
        ))
        
        # Section heading
        styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=self.colors.PRIMARY,
            spaceBefore=20,
            spaceAfter=12,
            borderWidth=0,
            borderColor=self.colors.PRIMARY,
            borderPadding=0,
            borderRadius=0,
            leftIndent=0
        ))
        
        # Subsection heading
        styles.add(ParagraphStyle(
            name='SubsectionHeading',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=self.colors.SECONDARY,
            spaceBefore=12,
            spaceAfter=8
        ))
        
        # Body text
        styles.add(ParagraphStyle(
            name='AstraBodyText',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=self.colors.TEXT_PRIMARY,
            alignment=TA_JUSTIFY,
            spaceAfter=6
        ))
        
        # Small text
        styles.add(ParagraphStyle(
            name='SmallText',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=self.colors.TEXT_SECONDARY,
            spaceAfter=4
        ))
        
        # Emphasized text
        styles.add(ParagraphStyle(
            name='Emphasis',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            leading=14,
            textColor=self.colors.ACCENT,
            spaceAfter=6
        ))
        
        # Risk score display
        styles.add(ParagraphStyle(
            name='RiskScore',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=48,
            leading=52,
            textColor=self.colors.PRIMARY,
            alignment=TA_CENTER,
            spaceAfter=10
        ))
        
        return styles
    
    def _add_first_page_decoration(self, canvas: canvas.Canvas, doc, data):
        """Add header/footer decoration to first page."""
        canvas.saveState()
        
        # Top accent bar
        canvas.setFillColor(self.colors.PRIMARY)
        canvas.rect(0, A4[1] - 1*cm, A4[0], 1*cm, fill=True, stroke=False)
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(self.colors.TEXT_SECONDARY)
        canvas.drawString(2*cm, 1.5*cm, f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}")
        canvas.drawRightString(A4[0] - 2*cm, 1.5*cm, "CONFIDENTIAL - For Internal Use Only")
        
        # Page number
        canvas.setFont('Helvetica', 9)
        canvas.drawCentredString(A4[0] / 2, 1*cm, "1")
        
        canvas.restoreState()
    
    def _add_page_decoration(self, canvas: canvas.Canvas, doc, data):
        """Add header/footer decoration to subsequent pages."""
        canvas.saveState()
        
        # Header with accent line
        canvas.setStrokeColor(self.colors.PRIMARY)
        canvas.setLineWidth(2)
        canvas.line(2*cm, A4[1] - 2*cm, A4[0] - 2*cm, A4[1] - 2*cm)
        
        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(self.colors.PRIMARY)
        canvas.drawString(2*cm, A4[1] - 1.7*cm, "ASTRA Risk Assessment")
        
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(self.colors.TEXT_SECONDARY)
        risk_model = data['metadata'].get('risk_model', 'CWRS')
        canvas.drawRightString(A4[0] - 2*cm, A4[1] - 1.7*cm, f"Model: {risk_model}")
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.drawString(2*cm, 1.5*cm, f"Report ID: {data['metadata']['report_id']}")
        
        # Page number
        canvas.setFont('Helvetica', 9)
        page_num = canvas.getPageNumber()
        canvas.drawCentredString(A4[0] / 2, 1*cm, str(page_num))
        
        canvas.restoreState()
    
    def _add_cover_page(self, story: list, data: dict, styles):
        """Create an attractive cover page."""
        # Add vertical space
        story.append(Spacer(1, 4*cm))
        
        # Main title
        story.append(Paragraph("ASTRA", styles['CoverTitle']))
        story.append(Paragraph(
            "Application Security Threat & Risk Assessment",
            styles['CoverSubtitle']
        ))
        
        story.append(Spacer(1, 2*cm))
        
        # Risk score display box
        overall_risk = data['overall_risk']
        risk_model = overall_risk.get('model', 'CWRS')
        scale_max = "10" if risk_model in ['REI', 'HRP'] else "100"
        
        # Create a colored box for risk score
        risk_data = [[
            Paragraph(f"<font size=48><b>{overall_risk['score']}</b></font><font size=24>/{scale_max}</font>",
                     styles['Normal'])
        ], [
            Paragraph(f"<font size=18><b>{overall_risk['rating']}</b></font>", styles['Normal'])
        ]]
        
        risk_color = self._get_risk_color(overall_risk['rating'])
        risk_table = Table(risk_data, colWidths=[8*cm])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ROUNDEDCORNERS', [10, 10, 10, 10]),
            ('TOPPADDING', (0, 0), (-1, -1), 20),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
        ]))
        
        story.append(risk_table)
        story.append(Spacer(1, 2*cm))
        
        # Metadata in elegant format
        metadata_style = ParagraphStyle(
            'MetadataStyle',
            parent=styles['AstraBodyText'],
            fontSize=11,
            leading=16,
            alignment=TA_CENTER,
            textColor=self.colors.TEXT_PRIMARY
        )
        
        story.append(Paragraph(
            f"<b>Report Period:</b> {data['metadata']['timeframe']}",
            metadata_style
        ))
        story.append(Paragraph(
            f"<b>Assessment Model:</b> {risk_model}",
            metadata_style
        ))
        story.append(Paragraph(
            f"<b>Generated:</b> {data['metadata']['generated_at']}",
            metadata_style
        ))
        
        # Add exclusion notice if applicable
        if data.get('exclusion_stats', {}).get('excluded_count', 0) > 0:
            exclusion_count = data['exclusion_stats']['excluded_count']
            story.append(Spacer(1, 0.5*cm))
            exclusion_style = ParagraphStyle(
                'ExclusionNoticeStyle',
                parent=styles['AstraBodyText'],
                fontSize=10,
                leading=14,
                alignment=TA_CENTER,
                textColor=colors.HexColor('#FF6B35'),
                fontName='Helvetica-Bold'
            )
            story.append(Paragraph(
                f"⚠ WHAT-IF ANALYSIS: {exclusion_count} vulnerability exclusions applied",
                exclusion_style
            ))
        
        story.append(Spacer(1, 3*cm))
        
        # Confidentiality notice
        confidential_style = ParagraphStyle(
            'ConfidentialStyle',
            parent=styles['SmallText'],
            alignment=TA_CENTER,
            textColor=self.colors.TEXT_SECONDARY,
            fontSize=9
        )
        story.append(Paragraph(
            "<b>CONFIDENTIAL</b><br/>This report contains sensitive security information",
            confidential_style
        ))
        
        story.append(PageBreak())
    
    def _add_executive_summary(self, story: list, data: dict, styles):
        """Add executive summary with key metrics."""
        story.append(Paragraph("Executive Summary", styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))
        
        # Key metrics in cards
        summary = data['summary']
        overall_risk = data['overall_risk']
        
        # Create 2x2 grid of metric cards
        metrics_data = [
            [
                self._create_metric_card("Vulnerabilities", summary['total_vulnerabilities'], self.colors.PRIMARY),
                self._create_metric_card("Affected Entities", summary['total_entities'], self.colors.SECONDARY)
            ],
            [
                self._create_metric_card("High Risk Entities", summary['high_risk_entities'], self.colors.HIGH),
                self._create_metric_card("Critical Issues", summary['by_severity']['CRITICAL'], self.colors.CRITICAL)
            ]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[8*cm, 8*cm], rowHeights=[3.5*cm, 3.5*cm])
        metrics_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 1*cm))
        
        # Risk assessment summary text
        story.append(Paragraph("Assessment Overview", styles['SubsectionHeading']))
        
        risk_model = overall_risk.get('model', 'CWRS')
        if risk_model == 'REI':
            interpretation = self._get_rei_interpretation(overall_risk['score'])
        elif risk_model == 'HRP':
            interpretation = self._get_hrp_interpretation(overall_risk['score'])
        else:
            interpretation = self._get_cwrs_interpretation(overall_risk['score'])
        
        story.append(Paragraph(interpretation, styles['AstraBodyText']))
        story.append(Spacer(1, 0.5*cm))
        
        # Severity breakdown chart
        story.append(Paragraph("Vulnerability Distribution", styles['SubsectionHeading']))
        chart = self._create_severity_chart(summary['by_severity'])
        story.append(chart)
        
        story.append(PageBreak())
    
    def _create_metric_card(self, label: str, value: int, color):
        """Create a metric display card."""
        card_data = [[
            Paragraph(f"<font size=32 color='white'><b>{value}</b></font>", ParagraphStyle('temp', alignment=TA_CENTER))
        ], [
            Paragraph(f"<font size=11 color='white'>{label}</font>", ParagraphStyle('temp', alignment=TA_CENTER))
        ]]
        
        card_table = Table(card_data, colWidths=[7.5*cm], rowHeights=[2.2*cm, 1*cm])
        card_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (0, 0), 'TOP'),  # Align number to bottom of its cell
            ('VALIGN', (0, 1), (0, 1), 'BOTTOM'),     # Align label to top of its cell
            ('ROUNDEDCORNERS', [8, 8, 8, 8]),
            ('TOPPADDING', (0, 0), (-1, 0), 1),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 1), (-1, 1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, 1), 15),
        ]))
        
        return card_table
    
    def _create_severity_chart(self, severity_data: dict):
        """Create a beautiful bar chart for severity distribution."""
        drawing = Drawing(400, 200)
        
        chart = VerticalBarChart()
        chart.x = 50
        chart.y = 50
        chart.height = 125
        chart.width = 300
        chart.data = [[
            severity_data['CRITICAL'],
            severity_data['HIGH'],
            severity_data['MEDIUM'],
            severity_data['LOW']
        ]]
        chart.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
        chart.bars[0].fillColor = self.colors.CRITICAL
        chart.bars.strokeColor = None
        chart.valueAxis.valueMin = 0
        chart.categoryAxis.labels.boxAnchor = 'n'
        chart.categoryAxis.labels.dy = -8
        chart.valueAxis.labels.fontName = 'Helvetica'
        chart.valueAxis.labels.fontSize = 8
        chart.categoryAxis.labels.fontName = 'Helvetica-Bold'
        chart.categoryAxis.labels.fontSize = 10
        
        # Color code bars
        chart.bars[0].fillColor = self.colors.PRIMARY
        
        drawing.add(chart)
        return drawing
    
    def _add_risk_breakdown(self, story: list, data: dict, styles):
        """Add detailed risk component breakdown."""
        story.append(Paragraph("Risk Analysis Breakdown", styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))
        
        overall_risk = data['overall_risk']
        components = overall_risk['components']
        risk_model = overall_risk.get('model', 'CWRS')
        
        if risk_model == 'REI':
            self._add_rei_breakdown(story, components, styles)
        elif risk_model == 'HRP2':
            self._add_hrp_v2_breakdown(story, components, styles)
        elif risk_model == 'HRP':
            self._add_hrp_breakdown(story, components, styles)
        else:
            self._add_cwrs_breakdown(story, components, styles)
        
        story.append(PageBreak())
    
    def _add_rei_breakdown(self, story: list, components: dict, styles):
        """Add REI model breakdown with visual enhancements."""
        # Component table with better styling
        comp_data = [
            ['Component', 'Value', 'Impact'],
            [
                'Vulnerability Impact',
                f"{components.get('vulnerability_impact_points', 0):,.0f} pts",
                self._get_impact_indicator(components.get('vulnerability_impact_points', 0), 10000)
            ],
            [
                'Blast Radius',
                f"{components.get('blast_radius_multiplier', 1):.2f}×",
                self._get_impact_indicator(components.get('blast_radius_multiplier', 1), 10, is_multiplier=True)
            ],
            [
                'Threat Intelligence',
                f"{components.get('threat_multiplier', 1):.2f}×",
                'Active' if components.get('threat_multiplier', 1) > 1 else 'None'
            ],
            [
                'Remediation Debt',
                f"{components.get('remediation_debt_points', 0):,.0f} pts",
                self._get_impact_indicator(components.get('remediation_debt_points', 0), 5000)
            ],
            [
                'Total Risk Points',
                f"<b>{components.get('total_risk_points', 0):,.0f}</b>",
                ''
            ]
        ]
        
        comp_table = Table(comp_data, colWidths=[6*cm, 5*cm, 5*cm])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors.TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -2), self.colors.TABLE_ROW_EVEN),
            ('BACKGROUND', (0, -1), (-1, -1), self.colors.ACCENT),
            ('TEXTCOLOR', (0, -1), (-1, -1), colors.white),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors.DIVIDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [self.colors.TABLE_ROW_EVEN, colors.white]),
        ]))
        
        story.append(comp_table)
        story.append(Spacer(1, 1*cm))
        
        # Add explanation
        story.append(Paragraph(
            "The Risk Exposure Index (REI) uses a logarithmic scale from 1-10, where each point represents "
            "exponentially higher risk. This model emphasizes critical vulnerabilities and large blast radius scenarios.",
            styles['AstraBodyText']
        ))
    
    def _add_cwrs_breakdown(self, story: list, components: dict, styles):
        """Add CWRS model breakdown with visual enhancements."""
        comp_data = [
            ['Component', 'Score', 'Weight', 'Contribution'],
            [
                'Vulnerability Severity',
                f"{components['vulnerability_severity']:.1f}",
                '40%',
                f"{components['vulnerability_severity']:.1f}/40"
            ],
            [
                'Exploitability',
                f"{components['exploitability']:.1f}",
                '25%',
                f"{components['exploitability']:.1f}/25"
            ],
            [
                'Exposure',
                f"{components['exposure']:.1f}",
                '20%',
                f"{components['exposure']:.1f}/20"
            ],
            [
                'System Criticality',
                f"{components['criticality']:.1f}",
                '15%',
                f"{components['criticality']:.1f}/15"
            ]
        ]
        
        comp_table = Table(comp_data, colWidths=[6*cm, 3*cm, 3*cm, 4*cm])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors.TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors.DIVIDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors.TABLE_ROW_EVEN, colors.white]),
        ]))
        
        story.append(comp_table)
        story.append(Spacer(1, 1*cm))
        
        # Add explanation
        story.append(Paragraph(
            "The Composite Weighted Risk Score (CWRS) provides a balanced assessment on a 0-100% scale, "
            "combining multiple risk factors with carefully calibrated weights.",
            styles['AstraBodyText']
        ))
    
    def _add_hrp_breakdown(self, story: list, components: dict, styles):
        """Add HRP model breakdown with visual enhancements."""
        story.append(Paragraph("Holistic Risk Posture Components", styles['SubsectionHeading']))
        story.append(Spacer(1, 0.3*cm))
        
        # Component breakdown table
        comp_data = [
            [Paragraph("<b>Component</b>", styles['AstraBodyText']), 
             Paragraph("<b>Score</b>", styles['AstraBodyText']),
             Paragraph("<b>Description</b>", styles['AstraBodyText'])],
            [Paragraph("<b>Critical Vulnerabilities (50%)</b>", styles['AstraBodyText']), 
             Paragraph(f"<b>{components['critical_vulnerabilities']:.1f}</b>/100", styles['AstraBodyText']),
             Paragraph("Davis Security Score-weighted vulnerability assessment emphasizing critical severity", styles['SmallText'])],
            [Paragraph("<b>Topology Risk (25%)</b>", styles['AstraBodyText']),
             Paragraph(f"<b>{components['topology_risk']:.1f}</b>/100", styles['AstraBodyText']),
             Paragraph("Blast radius analysis: affected entities and vulnerable library ratio (supply chain)", styles['SmallText'])],
            [Paragraph("<b>Aging Factor (25%)</b>", styles['AstraBodyText']),
             Paragraph(f"<b>{components['aging_factor']:.1f}</b>/100", styles['AstraBodyText']),
             Paragraph("Remediation velocity: time-weighted penalty for unresolved vulnerabilities", styles['SmallText'])],
            [Paragraph("<b>Total Weighted Score</b>", styles['AstraBodyText']),
             Paragraph(f"<b>{components['total_weighted_score']:.1f}</b>/100", styles['AstraBodyText']),
             Paragraph("Combined score before 1-10 scale conversion", styles['SmallText'])]
        ]
        
        comp_table = Table(comp_data, colWidths=[5*cm, 3*cm, 8.5*cm])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors.TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, -1), (-1, -1), self.colors.DIVIDER),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors.DIVIDER),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.whitesmoke]),
        ]))
        
        story.append(comp_table)
        story.append(Spacer(1, 1*cm))
        
        # Add explanation
        story.append(Paragraph(
            "The Holistic Risk Posture (HRP) provides a 1-10 scale assessment focused on blast radius and "
            "supply chain risk. It emphasizes the interconnected nature of vulnerabilities, software component "
            "aging, and the potential impact across your topology.",
            styles['AstraBodyText']
        ))
    
    def _add_hrp_v2_breakdown(self, story: list, components: dict, styles):
        """Add HRP v2 model breakdown with visual enhancements."""
        story.append(Paragraph("Holistic Risk Posture v2.0 Components", styles['SubsectionHeading']))
        story.append(Spacer(1, 0.3*cm))
        
        # Component breakdown table
        comp_data = [
            [Paragraph("<font color='#d32f2f'><b>Component</b></font>", styles['AstraBodyText']), 
             Paragraph("<font color='#d32f2f'><b>Score</b></font>", styles['AstraBodyText']),
             Paragraph("<font color='#d32f2f'><b>Description</b></font>", styles['AstraBodyText'])],
            [Paragraph("<b>Vulnerabilities</b>", styles['AstraBodyText']), 
             Paragraph(f"<b>{components['vulnerability_score']:.2f}</b>", styles['AstraBodyText']),
             Paragraph("Power-dampened severity with exploitability multipliers and CVE bonus", styles['SmallText'])],
            [Paragraph("<b>Supply Chain</b>", styles['AstraBodyText']),
             Paragraph(f"<b>{components['supply_chain_score']:.2f}</b>", styles['AstraBodyText']),
             Paragraph("<b>HIGH IMPORTANCE:</b> Vulnerable libraries ratio using power-law analysis", styles['SmallText'])],
            [Paragraph("<b>Topology</b>", styles['AstraBodyText']),
             Paragraph(f"<b>{components['topology_score']:.2f}</b>", styles['AstraBodyText']),
             Paragraph("Blast radius, connectivity depth, and critical path (databases, services, K8s)", styles['SmallText'])],
            [Paragraph("<b>Aging</b>", styles['AstraBodyText']),
             Paragraph(f"<b>{components['aging_score']:.2f}</b>", styles['AstraBodyText']),
             Paragraph("Continuous time-weighted penalty for unresolved vulnerabilities", styles['SmallText'])]
        ]
        
        comp_table = Table(comp_data, colWidths=[4*cm, 3*cm, 2.5*cm, 7*cm])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors.TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (1, 0), (2, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors.DIVIDER),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
        ]))
        
        story.append(comp_table)
        story.append(Spacer(1, 1*cm))
        
        # Add explanation
        story.append(Paragraph(
            "The Holistic Risk Posture v2.0 (HRP2) provides a 0-100 scale assessment with enhanced sensitivity "
            "to vulnerability changes. Supply chain risk now has its own high-importance component (20%) focused "
            "on vulnerable library ratios. The topology component includes blast radius, BFS connectivity analysis "
            "for transitive risk, and critical path detection. Aging has reduced weight (5%) to emphasize "
            "immediate security posture over remediation velocity.",
            styles['AstraBodyText']
        ))
    
    def _add_vulnerability_analysis(self, story: list, data: dict, styles):
        """Add vulnerability analysis section."""
        story.append(Paragraph("Vulnerability Analysis", styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))
        
        summary = data['summary']
        by_sev = summary['by_severity']
        
        # Severity breakdown table with improved styling
        sev_data = [
            ['Severity Level', 'Count', 'Percentage', 'Status'],
            [
                Paragraph('<font color="#d32f2f"><b>● Critical</b></font>', styles['AstraBodyText']),
                str(by_sev['CRITICAL']),
                f"{self._calculate_percentage(by_sev['CRITICAL'], summary['total_vulnerabilities'])}%",
                'Immediate Action Required' if by_sev['CRITICAL'] > 0 else 'None Found'
            ],
            [
                Paragraph('<font color="#f57c00"><b>● High</b></font>', styles['AstraBodyText']),
                str(by_sev['HIGH']),
                f"{self._calculate_percentage(by_sev['HIGH'], summary['total_vulnerabilities'])}%",
                'Urgent' if by_sev['HIGH'] > 5 else 'Monitor'
            ],
            [
                Paragraph('<font color="#fbc02d"><b>● Medium</b></font>', styles['AstraBodyText']),
                str(by_sev['MEDIUM']),
                f"{self._calculate_percentage(by_sev['MEDIUM'], summary['total_vulnerabilities'])}%",
                'Scheduled Remediation'
            ],
            [
                Paragraph('<font color="#7cb342"><b>● Low</b></font>', styles['AstraBodyText']),
                str(by_sev['LOW']),
                f"{self._calculate_percentage(by_sev['LOW'], summary['total_vulnerabilities'])}%",
                'Monitor'
            ]
        ]
        
        sev_table = Table(sev_data, colWidths=[4*cm, 3*cm, 3*cm, 6*cm])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors.TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors.DIVIDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors.TABLE_ROW_EVEN, colors.white]),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        story.append(sev_table)
        story.append(Spacer(1, 1*cm))
        
        # Recommendations based on severity
        story.append(Paragraph("Recommended Actions", styles['SubsectionHeading']))
        recommendations = self._generate_recommendations(by_sev)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles['AstraBodyText']))
            story.append(Spacer(1, 0.2*cm))
        
        story.append(PageBreak())
    
    def _add_remediation_priorities(self, story: list, data: dict, styles):
        """Add remediation priorities showing top 5 vulnerabilities for top 3 PGIs."""
        story.append(Paragraph("Top Remediation Priorities by Process Group Instance", styles['SectionHeading']))
        story.append(Spacer(1, 0.3*cm))
        
        story.append(Paragraph(
            "The following shows the top 5 vulnerabilities for each of the highest-risk Process Group Instances (PGIs). "
            "Vulnerabilities are ranked by Davis Security Score, which provides context-aware risk assessment.",
            styles['AstraBodyText']
        ))
        story.append(Spacer(1, 0.5*cm))
        
        # Get entities sorted by risk score
        entities = data.get('entities', [])
        
        if not entities:
            story.append(Paragraph(
                "<i>No entities found for remediation priorities.</i>",
                styles['AstraBodyText']
            ))
            story.append(PageBreak())
            return
        
        # Sort entities by risk score and get top 3
        sorted_entities = sorted(entities, key=lambda e: e.get('risk_score', 0), reverse=True)
        top_entities = sorted_entities[:min(3, len(sorted_entities))]
        
        risk_model = data['overall_risk'].get('model', 'CWRS')
        scale_max = "10" if risk_model in ['REI', 'HRP'] else "100"
        
        # Create a table for each of the top PGIs
        for entity_idx, entity in enumerate(top_entities, 1):
            entity_name = entity.get('entity_name', 'Unknown')
            entity_id = entity.get('entity_id', '')
            entity_risk = entity.get('risk_score', 0)
            
            # Add entity header
            if entity_idx > 1:
                story.append(Spacer(1, 0.7*cm))
            
            story.append(Paragraph(
                f"<b>{entity_idx}. {entity_name}</b>",
                styles['SubsectionHeading']
            ))
            story.append(Paragraph(
                f"<font size=9>Risk Score: {entity_risk}/{scale_max} | {entity.get('vulnerability_count', 0)} vulnerabilities</font>",
                styles['SmallText']
            ))
            story.append(Spacer(1, 0.3*cm))
            
            # Get vulnerabilities for this entity and sort by Davis Score
            entity_vulns = entity.get('vulnerabilities', [])
            if not entity_vulns:
                story.append(Paragraph("<i>No vulnerabilities found for this entity.</i>", styles['SmallText']))
                continue
            
            # Sort by Davis Security Score (riskScore) and get top 5
            sorted_vulns = sorted(
                entity_vulns,
                key=lambda v: v.get('riskAssessment', {}).get('riskScore', 
                              v.get('riskAssessment', {}).get('baseRiskScore', 0)),
                reverse=True
            )[:5]
            
            # Create table for this entity's vulnerabilities
            table_data = [[
                Paragraph("<b>#</b>", styles['SmallText']),
                Paragraph("<b>Vulnerability</b>", styles['SmallText']),
                Paragraph("<b>Severity</b>", styles['SmallText']),
                Paragraph("<b>Davis Score</b>", styles['SmallText'])
            ]]
            
            for vuln_idx, vuln in enumerate(sorted_vulns, 1):
                # Format vulnerability title with hyperlink
                title = vuln.get('title', 'Unknown')
                cve_id = vuln.get('cveId')
                security_problem_id = vuln.get('securityProblemId', '')
                tenant_url = data.get('metadata', {}).get('tenant_url', '')
                
                # Create hyperlink to security problem if we have the URL and ID
                if security_problem_id and tenant_url:
                    sp_url = f"{tenant_url}/ui/security/vulnerabilities/{security_problem_id}"
                    if cve_id:
                        vuln_text = f"<b><link href='{sp_url}' color='blue'>{cve_id}</link></b><br/><font size=8>{title[:70]}{'...' if len(title) > 70 else ''}</font>"
                    else:
                        vuln_text = f"<font size=8><link href='{sp_url}' color='blue'>{title[:90]}{'...' if len(title) > 90 else ''}</link></font>"
                else:
                    if cve_id:
                        vuln_text = f"<b>{cve_id}</b><br/><font size=8>{title[:70]}{'...' if len(title) > 70 else ''}</font>"
                    else:
                        vuln_text = f"<font size=8>{title[:90]}{'...' if len(title) > 90 else ''}</font>"
                
                # Get risk assessment
                risk_assessment = vuln.get('riskAssessment', {})
                if not isinstance(risk_assessment, dict):
                    risk_assessment = {}
                
                # Color code severity
                severity = risk_assessment.get('riskLevel', 'UNKNOWN')
                severity_colors = {
                    'CRITICAL': self.colors.CRITICAL,
                    'HIGH': self.colors.HIGH,
                    'MEDIUM': self.colors.MODERATE,
                    'LOW': self.colors.LOW
                }
                severity_color = severity_colors.get(severity, self.colors.TEXT_PRIMARY)
                severity_text = f"<font color='{severity_color.hexval()}'><b>{severity}</b></font>"
                
                # Get Davis Security Score
                davis_score = risk_assessment.get('riskScore', risk_assessment.get('baseRiskScore', 0))
                score_text = f"<b>{davis_score:.1f}/10</b>"
                
                table_data.append([
                    Paragraph(f"<b>{vuln_idx}</b>", styles['SmallText']),
                    Paragraph(vuln_text, styles['SmallText']),
                    Paragraph(severity_text, styles['SmallText']),
                    Paragraph(score_text, styles['SmallText'])
                ])
            
            # Create table for this PGI
            col_widths = [0.8*cm, 9*cm, 2.5*cm, 2.5*cm]
            pgi_table = Table(table_data, colWidths=col_widths)
            pgi_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.colors.TABLE_HEADER),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 0.5, self.colors.DIVIDER),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.colors.TABLE_ROW_EVEN]),
                ('TOPPADDING', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ]))
            
            story.append(pgi_table)
        
        story.append(Spacer(1, 0.5*cm))
        
        # Add note about Davis Security Score
        story.append(Paragraph(
            f"<b>Note:</b> Davis Security Score is a context-aware risk assessment (0-10 scale) that considers "
            f"attack detectability, exploit complexity, and environmental factors beyond traditional CVSS scoring. "
            f"Vulnerabilities are sorted by Davis Score to prioritize the most critical issues.",
            ParagraphStyle('NoteStyle', parent=styles['SmallText'], textColor=self.colors.TEXT_SECONDARY, fontSize=8)
        ))
        
        story.append(PageBreak())
    
    def _add_entity_details(self, story: list, data: dict, styles):
        """Add entity risk details with improved styling."""
        story.append(Paragraph("High-Risk Entities", styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))
        
        # Sort and filter entities
        entities = sorted(data['entities'], key=lambda x: x['risk_score'], reverse=True)
        high_risk_entities = [e for e in entities if e['risk_rating'] in ['HIGH', 'CRITICAL']][:10]
        
        if not high_risk_entities:
            story.append(Paragraph(
                "No high-risk entities identified. All entities are within acceptable risk thresholds.",
                styles['AstraBodyText']
            ))
            story.append(PageBreak())
            return
        
        risk_model = data['overall_risk'].get('model', 'CWRS')
        scale_max = "10" if risk_model in ['REI', 'HRP'] else "100"
        
        # Entity table with optimized column widths
        entity_data = [[
            Paragraph('<b>Entity Name</b>', styles['SmallText']),
            Paragraph('<b>Risk Score</b>', styles['SmallText']),
            Paragraph('<b>Rating</b>', styles['SmallText']),
            Paragraph('<b>Vulnerabilities</b>', styles['SmallText'])
        ]]
        
        for entity in high_risk_entities:
            # Truncate entity name intelligently
            entity_name = entity['entity_name']
            if len(entity_name) > 60:
                # Try to keep meaningful parts
                entity_name = entity_name[:57] + '...'
            
            entity_data.append([
                Paragraph(f"<font size=8>{entity_name}</font>", styles['SmallText']),
                Paragraph(f"<b>{entity['risk_score']:.1f}</b>/{scale_max}", styles['SmallText']),
                self._format_risk_rating(entity['risk_rating']),
                Paragraph(f"<b>{entity['vulnerability_count']}</b>", styles['SmallText'])
            ])
        
        entity_table = Table(entity_data, colWidths=[9*cm, 2.5*cm, 2.5*cm, 2*cm])
        entity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors.TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors.DIVIDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors.TABLE_ROW_EVEN, colors.white]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        story.append(entity_table)
        story.append(PageBreak())
    
    def _add_methodology_page(self, story: list, data: dict, styles):
        """Add methodology explanation page."""
        story.append(Paragraph("Assessment Methodology", styles['SectionHeading']))
        story.append(Spacer(1, 0.5*cm))
        
        risk_model = data['overall_risk'].get('model', 'CWRS')
        
        if risk_model == 'REI':
            story.append(Paragraph("Risk Exposure Index (REI)", styles['SubsectionHeading']))
            story.append(Paragraph(
                "REI uses a logarithmic scale from 1-10, similar to the Richter scale, where each point "
                "represents exponentially higher risk. This model emphasizes critical vulnerabilities and "
                "large blast radius scenarios through sophisticated point accumulation and multipliers.",
                styles['AstraBodyText']
            ))
            story.append(Spacer(1, 0.5*cm))
            
            story.append(Paragraph("Calculation Formula:", styles['SubsectionHeading']))
            story.append(Paragraph(
                "<i>REI Score = log₁₀(Total Risk Points + 1) × 1.5</i>",
                styles['AstraBodyText']
            ))
            story.append(Spacer(1, 0.3*cm))
            
            story.append(Paragraph("Components:", styles['SubsectionHeading']))
            story.append(Paragraph("1. <b>Vulnerability Impact:</b> Based on Davis Security Score (context-aware)", styles['AstraBodyText']))
            story.append(Paragraph("2. <b>Blast Radius:</b> Exponential multiplier based on affected entities", styles['AstraBodyText']))
            story.append(Paragraph("3. <b>Threat Intelligence:</b> Active exploit multiplier", styles['AstraBodyText']))
            story.append(Paragraph("4. <b>Remediation Debt:</b> Age-based penalty for unresolved issues", styles['AstraBodyText']))
        
        elif risk_model == 'HRP2':
            story.append(Paragraph("Holistic Risk Posture v2.0 (HRP2)", styles['SubsectionHeading']))
            story.append(Paragraph(
                "HRP2 provides a comprehensive 0-100 scale assessment with enhanced sensitivity to vulnerability changes. "
                "It uses power-law dampening to balance large vulnerability counts while maintaining visible risk reduction "
                "when vulnerabilities are remediated. This model emphasizes supply chain security and transitive risk through "
                "connectivity analysis.",
                styles['AstraBodyText']
            ))
            story.append(Spacer(1, 0.5*cm))
            
            story.append(Paragraph("Mathematical Foundation:", styles['SubsectionHeading']))
            story.append(Paragraph(
                "<i>Overall Score = 0.60 × S<sub>vuln</sub> + 0.20 × S<sub>supply</sub> + 0.15 × S<sub>topo</sub> + 0.05 × S<sub>aging</sub></i>",
                styles['AstraBodyText']
            ))
            story.append(Spacer(1, 0.3*cm))
            
            story.append(Paragraph("Component Formulas:", styles['SubsectionHeading']))
            story.append(Paragraph(
                "• <b>Vulnerabilities (60%):</b> S<sub>vuln</sub> = 100 × (Σ<sub>weighted</sub><sup>0.75</sup>) / (300<sup>0.75</sup>)",
                styles['AstraBodyText']
            ))
            story.append(Paragraph(
                "&nbsp;&nbsp;&nbsp;&nbsp;Uses power-law dampening (exponent 0.75) with exploitability multipliers (3.0×) and CVE bonus (2.2×)",
                styles['SmallText']
            ))
            story.append(Spacer(1, 0.2*cm))
            
            story.append(Paragraph(
                "• <b>Supply Chain (20% - HIGH IMPORTANCE):</b> S<sub>supply</sub> = 100 × (vulnerable_ratio<sup>0.7</sup>)",
                styles['AstraBodyText']
            ))
            story.append(Paragraph(
                "&nbsp;&nbsp;&nbsp;&nbsp;Ratio of vulnerable packages to total detected software components using power-law scaling",
                styles['SmallText']
            ))
            story.append(Spacer(1, 0.2*cm))
            
            story.append(Paragraph(
                "• <b>Topology (15%):</b> S<sub>topo</sub> = 0.40 × S<sub>blast</sub> + 0.35 × S<sub>connectivity</sub> + 0.25 × S<sub>critical</sub>",
                styles['AstraBodyText']
            ))
            story.append(Paragraph(
                "&nbsp;&nbsp;&nbsp;&nbsp;- Blast radius: 100 × (1 - e<sup>-0.05×entities</sup>) [exponential growth]",
                styles['SmallText']
            ))
            story.append(Paragraph(
                "&nbsp;&nbsp;&nbsp;&nbsp;- Connectivity: BFS graph traversal up to 3 hops for transitive risk",
                styles['SmallText']
            ))
            story.append(Paragraph(
                "&nbsp;&nbsp;&nbsp;&nbsp;- Critical path: Detects databases, services, and Kubernetes clusters",
                styles['SmallText']
            ))
            story.append(Spacer(1, 0.2*cm))
            
            story.append(Paragraph(
                "• <b>Aging (5%):</b> S<sub>aging</sub> = Σ [(days/365) × severity_weight × 0.7]",
                styles['AstraBodyText']
            ))
            story.append(Paragraph(
                "&nbsp;&nbsp;&nbsp;&nbsp;Continuous time penalty based on first detection in Dynatrace (CRITICAL=15, HIGH=8, MEDIUM=3, LOW=1)",
                styles['SmallText']
            ))
            story.append(Spacer(1, 0.5*cm))
            
            story.append(Paragraph("Example Calculation:", styles['SubsectionHeading']))
            story.append(Paragraph(
                "For 70 vulnerabilities (35 HIGH, 35 MEDIUM) across 50 affected entities with 30% supply chain risk:",
                styles['AstraBodyText']
            ))
            story.append(Paragraph(
                "• Vulnerability score: ~85/100 (power dampening prevents saturation)",
                styles['SmallText']
            ))
            story.append(Paragraph(
                "• Supply chain: 30/100 (30% vulnerable library ratio)",
                styles['SmallText']
            ))
            story.append(Paragraph(
                "• Topology: ~45/100 (50 entities + connectivity)",
                styles['SmallText']
            ))
            story.append(Paragraph(
                "• Aging: ~60/100 (6-month average age)",
                styles['SmallText']
            ))
            story.append(Paragraph(
                "<b>→ Overall: 0.60×85 + 0.20×30 + 0.15×45 + 0.05×60 = 63.75 [HIGH]</b>",
                styles['AstraBodyText']
            ))
            story.append(Spacer(1, 0.3*cm))
            
            story.append(Paragraph("Sensitivity:", styles['SubsectionHeading']))
            story.append(Paragraph(
                "Remediating 10 vulnerabilities typically reduces the score by 5-8 points, with visible "
                "rating changes when crossing thresholds (CRITICAL≥85, HIGH≥65, MEDIUM≥40, LOW≥20, MINIMAL<20).",
                styles['AstraBodyText']
            ))
        
        elif risk_model == 'HRP':
            story.append(Paragraph("Holistic Risk Posture v1.0 (HRP)", styles['SubsectionHeading']))
            story.append(Paragraph(
                "HRP provides a 1-10 scale assessment focused on blast radius and supply chain risk. "
                "It emphasizes the interconnected nature of vulnerabilities and software component aging.",
                styles['AstraBodyText']
            ))
            story.append(Spacer(1, 0.5*cm))
            
            story.append(Paragraph("Weighted Components (0-100 intermediate scale):", styles['SubsectionHeading']))
            story.append(Paragraph("• <b>Critical Vulnerabilities (50%):</b> Threshold-based severity scoring", styles['AstraBodyText']))
            story.append(Paragraph("• <b>Topology Risk (25%):</b> Blast radius and supply chain analysis", styles['AstraBodyText']))
            story.append(Paragraph("• <b>Aging Factor (25%):</b> Time-weighted penalty for unresolved issues", styles['AstraBodyText']))
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("The 0-100 intermediate score is converted to 1-10 scale with threshold mapping.", styles['SmallText']))
        
        else:
            story.append(Paragraph("Composite Weighted Risk Score (CWRS)", styles['SubsectionHeading']))
            story.append(Paragraph(
                "CWRS provides a balanced assessment on a 0-100% scale, combining multiple risk factors "
                "with carefully calibrated weights to provide a comprehensive view of application security posture.",
                styles['AstraBodyText']
            ))
            story.append(Spacer(1, 0.5*cm))
            
            story.append(Paragraph("Weighted Components:", styles['SubsectionHeading']))
            story.append(Paragraph("• <b>Vulnerability Severity (40%):</b> CVE-based severity assessment", styles['AstraBodyText']))
            story.append(Paragraph("• <b>Exploitability (25%):</b> Public exposure and exploit availability", styles['AstraBodyText']))
            story.append(Paragraph("• <b>Exposure (20%):</b> Attack surface and network accessibility", styles['AstraBodyText']))
            story.append(Paragraph("• <b>System Criticality (15%):</b> Business impact and resource footprint", styles['AstraBodyText']))
        
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("Data Source", styles['SubsectionHeading']))
        story.append(Paragraph(
            "This assessment leverages Dynatrace Application Security to provide real-time vulnerability "
            "detection with context-aware risk scoring using Davis Security Score, which considers attack "
            "complexity, network exposure, data assets, and exploitability.",
            styles['AstraBodyText']
        ))
    
    # Helper methods
    
    def _get_risk_color(self, rating: str):
        """Get color for risk rating."""
        color_map = {
            'CRITICAL': self.colors.CRITICAL,
            'HIGH': self.colors.HIGH,
            'ELEVATED': self.colors.HIGH,
            'MODERATE': self.colors.MODERATE,
            'LOW': self.colors.LOW,
            'MINIMAL': self.colors.MINIMAL
        }
        return color_map.get(rating, self.colors.TEXT_SECONDARY)
    
    def _format_risk_rating(self, rating: str):
        """Format risk rating with color."""
        color = self._get_risk_color(rating)
        return Paragraph(f'<font color="{color.hexval()}"><b>{rating}</b></font>', 
                        ParagraphStyle('temp', fontSize=9, alignment=TA_CENTER))
    
    def _get_impact_indicator(self, value: float, threshold: float, is_multiplier: bool = False):
        """Get visual indicator for impact level."""
        if is_multiplier:
            if value >= 10:
                return "●●●●● Extreme"
            elif value >= 5:
                return "●●●● Very High"
            elif value >= 2:
                return "●●● High"
            elif value > 1:
                return "●● Moderate"
            else:
                return "● Low"
        else:
            if value >= threshold * 5:
                return "●●●●● Extreme"
            elif value >= threshold * 2:
                return "●●●● Very High"
            elif value >= threshold:
                return "●●● High"
            elif value >= threshold * 0.5:
                return "●● Moderate"
            else:
                return "● Low"
    
    def _calculate_percentage(self, value: int, total: int) -> str:
        """Calculate percentage safely."""
        if total == 0:
            return "0"
        return f"{(value / total * 100):.1f}"
    
    def _get_rei_interpretation(self, score: float) -> str:
        """Get interpretation text for REI score."""
        if score >= 8.6:
            return ("Critical risk level detected. Immediate executive attention and emergency response plan activation required. "
                   "Multiple critical vulnerabilities with large blast radius indicate severe security exposure.")
        elif score >= 7.1:
            return ("High risk level requiring urgent action. Prioritize remediation within 7 days. "
                   "Significant vulnerabilities detected with notable blast radius.")
        elif score >= 5.1:
            return ("Elevated risk level. Schedule comprehensive remediation within 30 days. "
                   "Multiple vulnerabilities present but manageable with proper planning.")
        elif score >= 3.1:
            return ("Moderate risk level. Standard remediation procedures apply. "
                   "Continue monitoring and address vulnerabilities in regular maintenance cycles.")
        else:
            return ("Low risk level. Maintain current security posture. "
                   "Minimal vulnerabilities detected with limited exposure.")
    
    def _get_cwrs_interpretation(self, score: float) -> str:
        """Get interpretation text for CWRS score."""
        if score >= 71:
            return ("Critical risk level (71-100%). Immediate action required. "
                   "Security posture requires urgent attention with comprehensive remediation plan.")
        elif score >= 51:
            return ("High risk level (51-70%). Prioritize security improvements. "
                   "Multiple risk factors contribute to elevated overall risk score.")
        elif score >= 26:
            return ("Moderate risk level (26-50%). Manageable security posture. "
                   "Continue monitoring and implement scheduled improvements.")
        else:
            return ("Low risk level (0-25%). Security posture is acceptable. "
                   "Maintain current controls and continue routine monitoring.")
    
    def _get_hrp_interpretation(self, score: float) -> str:
        """Get interpretation text for HRP score."""
        if score >= 8.5:
            return ("Critical holistic risk detected. Supply chain and blast radius analysis indicates severe exposure. "
                   "Immediate action required across software component inventory and connected services. "
                   "Long-standing vulnerabilities with high blast radius require executive-level intervention.")
        elif score >= 6.5:
            return ("High holistic risk level. Topology analysis shows significant interconnected risk. "
                   "Prioritize remediation focusing on most connected components and aging vulnerabilities. "
                   "Supply chain dependencies require attention within 14 days.")
        elif score >= 4.0:
            return ("Moderate holistic risk. Manageable security debt with some aging vulnerabilities. "
                   "Focus on library updates and component hygiene. Standard remediation cadence appropriate.")
        else:
            return ("Low holistic risk. Software component inventory well-maintained. "
                   "Limited blast radius and good remediation velocity. Continue current practices.")
    
    def _generate_recommendations(self, severity_data: dict) -> list:
        """Generate actionable recommendations based on severity data."""
        recommendations = []
        
        if severity_data['CRITICAL'] > 0:
            recommendations.append(
                f"<b>URGENT:</b> Address {severity_data['CRITICAL']} critical vulnerabilities immediately. "
                "Activate incident response procedures and consider temporary mitigations."
            )
        
        if severity_data['HIGH'] > 10:
            recommendations.append(
                f"<b>HIGH PRIORITY:</b> Develop remediation plan for {severity_data['HIGH']} high-severity vulnerabilities. "
                "Target completion within 14 days."
            )
        elif severity_data['HIGH'] > 0:
            recommendations.append(
                f"<b>PRIORITY:</b> Address {severity_data['HIGH']} high-severity vulnerabilities within 30 days."
            )
        
        if severity_data['MEDIUM'] > 20:
            recommendations.append(
                f"<b>ATTENTION:</b> {severity_data['MEDIUM']} medium-severity vulnerabilities require systematic remediation. "
                "Consider automated patching where applicable."
            )
        
        if severity_data['LOW'] > 50:
            recommendations.append(
                f"<b>MAINTENANCE:</b> Large number ({severity_data['LOW']}) of low-severity issues. "
                "Implement automated dependency updates and regular maintenance cycles."
            )
        
        if not recommendations:
            recommendations.append(
                "<b>MAINTAIN:</b> Continue current security practices. "
                "No immediate vulnerabilities requiring urgent attention."
            )
        
        return recommendations
