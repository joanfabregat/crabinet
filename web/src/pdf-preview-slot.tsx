/**
 * The PDF preview slot. The panel shows this placeholder and relies on the
 * file toolbar's Open in new tab and Download actions; a first-page renderer
 * can replace it without changing the panel.
 */
export function PdfPreview({ filename }: { url: string; filename: string }) {
  return (
    <div
      class="pdf-preview"
      role="note"
      aria-label={`PDF preview of ${filename}`}
    >
      <p class="status-message">PDF preview</p>
      <p class="pdf-preview-hint">
        Open the PDF in a new tab to read it in your browser, or download it.
      </p>
    </div>
  );
}
