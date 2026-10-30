# OGDE brand assets

These files are the single source of truth for the OGDE mark. Sites, documentation, packages and future builds should reference them here, not redraw or recolour the wordmark.

The master artwork is the unmodified JPEG supplied with the brand: navy **OGDE** on white, with the subtitle “One Global Defence Ecosystem”.

## Colours

| Name | Hex | Use |
| --- | --- | --- |
| Navy | `#052355` | Wordmark. RGB 5, 35, 85. |
| Subtitle grey | `#717580` | Sampled from the master artwork’s subtitle. |
| White | `#FFFFFF` | Master background. |

Do not recolour the wordmark. Body text on a page may use navy or a darker grey for contrast; that text is not the logo.

## Files

| File | What it is |
| --- | --- |
| `ogde-logo.jpg` | Original master JPEG, byte-for-byte. SHA-256 `880e5d9a825c6958ee082a49e97cfef4f55fc63489535170af23269f1fe87f73`. |
| `ogde-logo.png` | Same lockup with a transparent background, cropped, colours snapped to the values above. |
| `ogde-logo.svg` | Vector trace of that lockup. The wordmark is `#052355` and the subtitle is `#717580`. |
| `ogde-icon.svg` | The letter O taken from the wordmark, navy on a transparent background. |
| `ogde-icon.png` | 512×512 transparent O, for use on a light background. |
| `ogde-icon-32.png` | 32×32 favicon preview: white O on a navy rounded square, so it remains legible at tab size. |
| `ogde-icon-180.png` | 180×180 touch icon, same reversed treatment. |
| `favicon.ico` | 16×16 and 32×32, same reversed treatment. |

The SVG is a trace of the master pixels, not a redraw in a different typeface. Prefer the PNG in contexts that do not render SVG, including the GitHub README.

## Stable URLs

After this tree is on `main`, these raw URLs are the permanent references:

- https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/ogde-logo.jpg
- https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/ogde-logo.png
- https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/ogde-logo.svg
- https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/ogde-icon.svg
- https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/ogde-icon.png
- https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/ogde-icon-32.png
- https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/ogde-icon-180.png
- https://raw.githubusercontent.com/ymmiah/OGDE/main/assets/brand/favicon.ico

They resolve only once the files are on the default branch. Do not copy the artwork into another directory for a one-off build; link to these paths or to the files in this folder.
