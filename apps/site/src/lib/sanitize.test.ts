import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { sanitizeRichText } from "./sanitize.ts";

const IMG = "https://images.microcms-assets.io/assets/abc/def/photo.jpg";

/** Asserts that the output has no executable or style-bearing markup. */
function assertInert(output: string): void {
  const lower = output.toLowerCase();
  for (const needle of ["<script", "<style", "<iframe", "<svg", "<object", "<embed", "<form", "javascript:", "data:", "vbscript:", " on", "style="]) {
    assert.equal(lower.includes(needle), false, `output contains ${JSON.stringify(needle)}: ${output}`);
  }
}

describe("sanitizeRichText keeps microCMS rich-editor output", () => {
  const cases: Array<[string, string]> = [
    ['<h1 id="h634aaf8fde">見出し1</h1>', '<h1 id="h634aaf8fde">見出し1</h1>'],
    ['<h5 id="h1">見出し5</h5>', '<h5 id="h1">見出し5</h5>'],
    ["<p>Shift + Enterを押すと<br>改行になります。</p>", "<p>Shift + Enterを押すと<br />改行になります。</p>"],
    ["<hr>", "<hr />"],
    ["<blockquote><p>引用</p></blockquote>", "<blockquote><p>引用</p></blockquote>"],
    [
      "<p><strong>b</strong><em>i</em><u>u</u><s>s</s><code>c</code></p>",
      "<p><strong>b</strong><em>i</em><u>u</u><s>s</s><code>c</code></p>",
    ],
    ['<p><span class="highlight">h</span></p>', '<p><span class="highlight">h</span></p>'],
    [
      '<div data-filename="a.js"><pre><code class="language-javascript">const a = 1 &lt; 2;</code></pre></div>',
      '<div data-filename="a.js"><pre><code class="language-javascript">const a = 1 &lt; 2;</code></pre></div>',
    ],
    [
      "<ul><li>a<ul><li>b</li></ul></li></ul><ol><li>c</li></ol>",
      "<ul><li>a<ul><li>b</li></ul></li></ul><ol><li>c</li></ol>",
    ],
    [
      '<table><tbody><tr><th colspan="1" rowspan="1"><p>h</p></th><td colspan="2" rowspan="1"><p>d</p></td></tr></tbody></table>',
      '<table><tbody><tr><th colspan="1" rowspan="1"><p>h</p></th><td colspan="2" rowspan="1"><p>d</p></td></tr></tbody></table>',
    ],
    ['<p><a href="https://example.com/">l</a></p>', '<p><a href="https://example.com/">l</a></p>'],
    [
      '<p><a href="https://example.com/" target="_blank" rel="noopener noreferrer nofollow">l</a></p>',
      '<p><a href="https://example.com/" target="_blank" rel="nofollow noopener noreferrer">l</a></p>',
    ],
    ['<p><a href="/projects/a/">l</a></p>', '<p><a href="/projects/a/">l</a></p>'],
    ['<p><a href="#h1">l</a></p>', '<p><a href="#h1">l</a></p>'],
    ['<p><a href="mailto:a@example.com">m</a></p>', '<p><a href="mailto:a@example.com">m</a></p>'],
    [
      `<figure><a href="https://example.com/"><img src="${IMG}" alt="a" width="800" height="600"></a><figcaption>c</figcaption></figure>`,
      `<figure><a href="https://example.com/"><img src="${IMG}" alt="a" width="800" height="600" /></a><figcaption>c</figcaption></figure>`,
    ],
    ["<p>&amp; &lt; &gt; &quot; &#39;</p>", "<p>&amp; &lt; &gt; \" '</p>"],
  ];
  for (const [input, expected] of cases) {
    it(input, () => assert.equal(sanitizeRichText(input), expected));
  }
});

describe("sanitizeRichText removes styling and embeds", () => {
  it("drops style attributes", () => {
    assert.equal(
      sanitizeRichText('<p style="text-align: center"><span style="color: #ff0000">t</span></p>'),
      "<p><span>t</span></p>",
    );
    assert.equal(
      sanitizeRichText(`<figure style="text-align: left;"><img src="${IMG}" alt=""></figure>`),
      `<figure><img src="${IMG}" alt="" /></figure>`,
    );
  });

  it("drops embed iframes with their wrapper style", () => {
    assert.equal(
      sanitizeRichText(
        '<div style="position:relative"><iframe src="https://www.youtube.com/embed/x" style="border:0" allowfullscreen scrolling="no" allow="autoplay"></iframe></div>',
      ),
      "<div></div>",
    );
  });

  it("drops file-link data attributes but keeps the link", () => {
    assert.equal(
      sanitizeRichText('<a href="https://files.microcms-assets.io/a.pdf" target="_blank" data-embed-type="file" data-mime-type="application/pdf">f</a>'),
      '<a href="https://files.microcms-assets.io/a.pdf" target="_blank" rel="noopener noreferrer">f</a>',
    );
  });

  it("drops classes on code that are not language-*", () => {
    assert.equal(sanitizeRichText('<code class="x language-js">c</code>'), '<code class="language-js">c</code>');
  });

  it("drops target values other than _blank and unknown rel tokens", () => {
    assert.equal(
      sanitizeRichText('<a href="https://e.com/" target="_top" rel="opener external">l</a>'),
      '<a href="https://e.com/">l</a>',
    );
    assert.equal(
      sanitizeRichText('<a href="https://e.com/" target=" _BLANK ">l</a>'),
      '<a href="https://e.com/" target="_blank" rel="noopener noreferrer">l</a>',
    );
  });
});

describe("sanitizeRichText neutralises malicious input", () => {
  const attacks = [
    "<script>alert(1)</script>",
    "<SCRIPT SRC=//evil.example/x.js></SCRIPT>",
    "<p>a<script>alert(1)</script>b</p>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<style>body{display:none}</style>",
    '<img src="x" onerror="alert(1)">',
    '<img src=x onerror=alert(1)//>',
    '<p onclick="alert(1)" ONMOUSEOVER="alert(1)">t</p>',
    '<a href="javascript:alert(1)">x</a>',
    '<a href="JaVaScRiPt:alert(1)">x</a>',
    '<a href="  javascript:alert(1)">x</a>',
    '<a href="java\tscript:alert(1)">x</a>',
    '<a href="java\nscript:alert(1)">x</a>',
    '<a href="jav&#x61;script:alert(1)">x</a>',
    '<a href="jav&#97;script:alert(1)">x</a>',
    '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">x</a>',
    '<a href="javascript&colon;alert(1)">x</a>',
    '<a href="vbscript:msgbox(1)">x</a>',
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">x</a>',
    '<img src="data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=">',
    '<img src="javascript:alert(1)">',
    '<svg><script>alert(1)</script></svg>',
    '<svg onload="alert(1)"><circle r="1"/></svg>',
    '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
    '<iframe src="https://evil.example/"></iframe>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<object data="javascript:alert(1)"></object>',
    '<embed src="javascript:alert(1)">',
    '<form action="https://evil.example/"><input name="q"><button>go</button></form>',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>',
    '<template><img src=x onerror=alert(1)></template>',
    '<p title="x&quot; onmouseover=&quot;alert(1)">t</p>',
    "<p title='x\" onmouseover=\"alert(1)'>t</p>",
    '<span class="a" style="background:url(javascript:alert(1))">t</span>',
    '<!--<img src=x onerror=alert(1)>-->',
    '<!-- --!><img src=x onerror=alert(1)>-->',
    '<a href="https://e.com/" style="position:fixed;inset:0">x</a>',
    '<base href="https://evil.example/">',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<link rel="stylesheet" href="https://evil.example/x.css">',
    '<img srcset="javascript:alert(1) 1x" src="https://e.com/a.png">',
    '<a href="//evil.example/">x</a>',
    "<textarea><img src=x onerror=alert(1)></textarea>",
    '<div data-filename="a" onclick="alert(1)" id="x">t</div>',
  ];
  for (const input of attacks) {
    it(input, () => assertInert(sanitizeRichText(input)));
  }

  it("keeps the text around removed scripts only", () => {
    assert.equal(sanitizeRichText("<p>a<script>alert(1)</script>b</p>"), "<p>ab</p>");
  });

  it("drops protocol-relative URLs", () => {
    assert.equal(sanitizeRichText('<a href="//evil.example/">x</a>'), "<a>x</a>");
  });

  it("escapes quotes in attribute values", () => {
    const output = sanitizeRichText("<a href='https://e.com/?q=\"><img src=x onerror=alert(1)>'>x</a>");
    assert.equal(output.includes("<img"), false, output);
  });
});
