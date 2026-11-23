// Loads the site content once per build from CONTENT_DIR / CONTENT_MODE.

import { loadContent, resolveSource, type SiteContent } from "./content.ts";

declare const __CONTENT_FIXTURE_DIR__: string;

let cached: Promise<SiteContent> | undefined;

/** Returns the validated content; logs counts only. */
export function getSiteContent(): Promise<SiteContent> {
  cached ??= (async () => {
    const source = resolveSource(process.env, __CONTENT_FIXTURE_DIR__);
    const { content, dropped } = await loadContent(source.dir, source.mode);
    const origin = source.fixture ? "fixture" : "CONTENT_DIR";
    console.log(`content: ${source.mode} mode (${origin}), ${content.projects.length} project(s)`);
    if (source.mode === "draft") console.log(`content: ${dropped} invalid item(s) dropped`);
    return content;
  })();
  return cached;
}
