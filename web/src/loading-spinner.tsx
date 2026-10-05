/**
 * A spinner centered over the preview area that is still loading, such as an
 * image, a PDF page, or a media element before its metadata arrives. Its
 * parent must be positioned. With reduced motion it is a static ring.
 */
export function LoadingSpinner() {
  return (
    <span
      class="preview-spinner"
      role="status"
      aria-label="Loading preview"
      data-testid="preview-spinner"
    />
  );
}
