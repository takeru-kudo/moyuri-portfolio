// Zod schemas for the microCMS JSON files written by tools/fetch-content.

import { z } from "zod";

export const SLUG_PATTERN = /^[a-z0-9]+(-[a-z0-9]+)*$/;

const dateTime = z.iso.datetime({ offset: true });

/** System fields of a content object. publishedAt/revisedAt are absent on never-published drafts. */
const systemFields = {
  createdAt: dateTime,
  updatedAt: dateTime,
  publishedAt: dateTime.optional(),
  revisedAt: dateTime.optional(),
};

const contentId = z.string().min(1);

const slug = z.string().min(1).max(64).regex(SLUG_PATTERN);

const optionalText = (max: number) => z.string().max(max).nullish();

export const mediaSchema = z.object({
  url: z.url({ protocol: /^https$/ }),
  width: z.number().int().positive().optional(),
  height: z.number().int().positive().optional(),
  alt: z.string().nullish(),
});

export const categorySchema = z.object({
  id: contentId,
  ...systemFields,
  name: z.string().min(1).max(50),
  slug,
});

export const projectSchema = z.object({
  id: contentId,
  ...systemFields,
  title: z.string().min(1).max(100),
  slug,
  cover: mediaSchema,
  summary: optionalText(300),
  body: z.string().nullish(),
  category: categorySchema.nullish(),
  order: z.number().int().min(0).max(9999).nullish(),
  featured: z.boolean().default(false),
});

export const profileSchema = z.object({
  ...systemFields,
  name: optionalText(50),
  bio: optionalText(2000),
});

export const siteSchema = z.object({
  ...systemFields,
  tagline: optionalText(100),
});

/** List file wrapper: totalCount equals contents.length; ids and slugs are unique. */
function listSchema<T extends z.ZodType<{ id: string; slug: string }>>(item: T) {
  return z
    .object({
      contents: z.array(item),
      totalCount: z.number().int().nonnegative(),
    })
    .superRefine((list, ctx) => {
      if (list.totalCount !== list.contents.length) {
        ctx.addIssue({
          code: "custom",
          path: ["totalCount"],
          message: "totalCount does not match the number of contents",
        });
      }
      const ids = new Set<string>();
      const slugs = new Set<string>();
      list.contents.forEach((entry, index) => {
        if (ids.has(entry.id)) {
          ctx.addIssue({ code: "custom", path: ["contents", index, "id"], message: "duplicate id" });
        }
        if (slugs.has(entry.slug)) {
          ctx.addIssue({ code: "custom", path: ["contents", index, "slug"], message: "duplicate slug" });
        }
        ids.add(entry.id);
        slugs.add(entry.slug);
      });
    });
}

export const categoriesFileSchema = listSchema(categorySchema);
export const projectsFileSchema = listSchema(projectSchema);
export const profileFileSchema = profileSchema;
export const siteFileSchema = siteSchema;

export type Media = z.output<typeof mediaSchema>;
export type Category = z.output<typeof categorySchema>;
export type Project = z.output<typeof projectSchema>;
export type Profile = z.output<typeof profileSchema>;
export type Site = z.output<typeof siteSchema>;
export type CategoriesFile = z.output<typeof categoriesFileSchema>;
export type ProjectsFile = z.output<typeof projectsFileSchema>;
