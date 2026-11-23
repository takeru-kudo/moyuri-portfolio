// Allow-list sanitiser for microCMS rich-text HTML rendered with set:html.

import sanitizeHtml from "sanitize-html";

const HEADINGS = ["h1", "h2", "h3", "h4", "h5"] as const;

const ALLOWED_TAGS = [
  "p",
  "br",
  "hr",
  ...HEADINGS,
  "blockquote",
  "strong",
  "em",
  "u",
  "s",
  "code",
  "pre",
  "div",
  "span",
  "ul",
  "ol",
  "li",
  "a",
  "figure",
  "figcaption",
  "img",
  "table",
  "tbody",
  "tr",
  "th",
  "td",
];

/** Elements removed together with their content. */
const DROPPED_WITH_CONTENT = [
  "script",
  "style",
  "iframe",
  "frame",
  "frameset",
  "object",
  "embed",
  "applet",
  "form",
  "input",
  "button",
  "select",
  "option",
  "textarea",
  "noscript",
  "noembed",
  "noframes",
  "template",
  "svg",
  "math",
  "title",
  "xmp",
  "plaintext",
];

const ALLOWED_REL = new Set(["noopener", "noreferrer", "nofollow"]);

const OPTIONS: sanitizeHtml.IOptions = {
  allowedTags: ALLOWED_TAGS,
  allowedAttributes: {
    ...Object.fromEntries(HEADINGS.map((tag) => [tag, ["id"]])),
    a: ["href", "target", "rel"],
    img: ["src", "alt", "width", "height"],
    div: ["data-filename"],
    span: ["class"],
    code: ["class"],
    th: ["colspan", "rowspan"],
    td: ["colspan", "rowspan"],
  },
  allowedClasses: {
    code: ["language-*"],
    span: ["*"],
  },
  allowedSchemes: ["http", "https", "mailto"],
  allowedSchemesByTag: { img: ["http", "https"] },
  allowedSchemesAppliedToAttributes: ["href", "src", "cite"],
  allowProtocolRelative: false,
  allowedStyles: {},
  allowVulnerableTags: false,
  disallowedTagsMode: "discard",
  nonTextTags: DROPPED_WITH_CONTENT,
  parseStyleAttributes: false,
  transformTags: { a: transformLink },
};

/** Keeps target only when it is _blank; then rel always contains noopener and noreferrer. */
function transformLink(tagName: string, attribs: sanitizeHtml.Attributes): sanitizeHtml.Tag {
  const { target, rel, ...rest } = attribs;
  const tokens = new Set(
    (rel ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter((token) => ALLOWED_REL.has(token)),
  );
  const attributes: sanitizeHtml.Attributes = { ...rest };
  if (target?.trim().toLowerCase() === "_blank") {
    attributes.target = "_blank";
    tokens.add("noopener");
    tokens.add("noreferrer");
  }
  if (tokens.size > 0) attributes.rel = [...tokens].sort().join(" ");
  return { tagName, attribs: attributes };
}

/** Returns the rich-text HTML with only allow-listed elements, attributes and URL schemes. */
export function sanitizeRichText(html: string): string {
  return sanitizeHtml(html, OPTIONS);
}
