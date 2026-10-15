"""The public face of the site: a small, believable personal blog (home, archive, about, posts,
sitemap, robots, favicon). Everything that is not a page of this site or of the panel gets the
ordinary "page not found"."""
from fastapi import HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

SITE_NAME = "Northfield Notes"
TAGLINE = "Short notes on software, writing and the things in between."

POSTS = [
    {"slug": "keeping-small-projects-small", "title": "Keeping small projects small", "date": "2026-09-14", "when": "September 2026", "mins": 4,
     "summary": "A few habits that help side projects survive past the first weekend: write the README first, ship the boring version, and delete more than you add.",
     "body": [
         "Most side projects do not die because they were hard. They die because they quietly grew. A weekend idea picks up a settings page, then a plugin system, then a name change, and by the second Sunday nobody wants to open the folder.",
         "The habit that helps me most is writing the README before any code. If I cannot explain in four sentences what the thing does and who it is for, I am not ready to build it. The README also becomes a promise I can check the work against.",
         "The second habit is shipping the boring version first. Hard-coded values, one input format, no configuration. It is almost always enough, and when it is not, the shape of the real need is much clearer than it was on day one.",
         "The last one is deleting more than I add. Every few weeks I look for a feature I have not touched and remove it. The project gets smaller, the code gets easier to read, and the things that remain are the ones that earned their place.",
     ]},
    {"slug": "notes-on-reading-slowly", "title": "Notes on reading slowly", "date": "2026-08-09", "when": "August 2026", "mins": 3,
     "summary": "Why a single chapter a day beats a weekend binge, and what changes when you keep a margin notebook next to the book.",
     "body": [
         "For years I measured reading by how many books I finished. It made me a faster reader and a worse one. I remembered plots for a week and arguments for about a day.",
         "These days I read one chapter, close the book, and write three lines in a small notebook: what the chapter claimed, one sentence I liked, and one thing I doubt. It takes five minutes and it changes how I read the next chapter, because I am now reading to answer those questions.",
         "Slow reading is not a virtue in itself. Some books deserve a fast, greedy afternoon. But for anything I want to still understand in a year, the margin notebook has been the single most useful tool I have added.",
     ]},
    {"slug": "a-tidy-home-server-revisited", "title": "A tidy home server, revisited", "date": "2026-06-21", "when": "June 2026", "mins": 6,
     "summary": "Backups, updates and one very small dashboard. Nothing clever, which is the point.",
     "body": [
         "I have run some kind of home server for a long time, and the best version of it is always the most boring one. A single small machine, a handful of services, and a routine I can follow when I am tired.",
         "Backups come first. Anything that matters is copied nightly to a second disk and weekly to somewhere outside the house. Once a quarter I restore one file from each, because a backup that has never been restored is only a hope.",
         "Updates are scheduled, not heroic. One evening a month I update everything, read what changed, and write one line in a changelog file. If something breaks, the changelog tells me what I touched last.",
         "The dashboard is a static page that lists what is running and when it last backed up. It has no login, no database and no JavaScript, and it has never once been the thing that went wrong.",
     ]},
    {"slug": "the-case-for-plain-text", "title": "The case for plain text", "date": "2026-04-30", "when": "April 2026", "mins": 5,
     "summary": "Notes, to-do lists and drafts all end up in one folder of text files. Here is why that keeps working when apps come and go.",
     "body": [
         "I have moved my notes between five applications in ten years, and each move cost me an afternoon and a few things that never came across. The folder of plain text files I started with has survived all of them.",
         "Plain text is easy to search, easy to back up and easy to read on any device. It does not need an account, it does not change its format, and I can open a file from 2016 as easily as one from yesterday.",
         "The trade-off is that there is no fancy structure. I solved that with a few conventions: one file per topic, the date at the top, and a short list of tags on the second line. It is not elegant, but it is durable, and durable is what I wanted.",
     ]},
    {"slug": "small-tools-for-writing", "title": "Small tools for writing", "date": "2026-03-12", "when": "March 2026", "mins": 4,
     "summary": "A timer, a word counter and a rule about the first paragraph. The tiny things that make a draft easier to start.",
     "body": [
         "I used to wait for the right mood to write, which meant I wrote very little. What changed things was lowering the cost of starting rather than raising the quality of the mood.",
         "A twenty-five minute timer is the first tool. I do not have to write well, only until it rings. A word counter in the corner is the second, because watching the number grow is more motivating than I would like to admit.",
         "The third is a rule: the first paragraph is allowed to be bad. I mark it with a line of asterisks and come back to it at the end, when I finally know what the piece is about. Most of the time, I cut it entirely.",
     ]},
]
BY_SLUG = {p["slug"]: p for p in POSTS}

ABOUT = [
    "Northfield Notes is a small personal site where I write about software, reading and the quiet habits that make work easier. It is written in my spare time and updated when I have something worth saying, which is not as often as I would like.",
    "There are no ads, no newsletter and no tracking here. If you enjoy something, tell a friend. If you spot a mistake, I would be glad to know.",
]

FAVICON = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='8' fill='#374151'/>"
           "<text x='16' y='22' font-family='Georgia,serif' font-size='18' text-anchor='middle' fill='#fafaf9'>N</text></svg>")


def register(app, templates):
    def page(request, view, **ctx):
        return templates.TemplateResponse(request, "site.html", {
            "view": view, "site_name": SITE_NAME, "tagline": TAGLINE, "posts": POSTS, **ctx})

    @app.api_route("/", methods=["GET", "HEAD"])
    def home(request: Request):
        return page(request, "home", recent=POSTS[:3], title=SITE_NAME)

    @app.api_route("/archive", methods=["GET", "HEAD"])
    def archive(request: Request):
        return page(request, "archive", title="Archive")

    @app.api_route("/about", methods=["GET", "HEAD"])
    def about(request: Request):
        return page(request, "about", about=ABOUT, title="About")

    @app.api_route("/notes/{slug}", methods=["GET", "HEAD"])
    def note(request: Request, slug: str):
        p = BY_SLUG.get(slug)
        if not p:
            raise HTTPException(404)
        i = POSTS.index(p)
        return page(request, "post", post=p, title=p["title"],
                    newer=POSTS[i - 1] if i > 0 else None, older=POSTS[i + 1] if i + 1 < len(POSTS) else None)

    @app.get("/favicon.ico")
    def favicon():
        return Response(FAVICON, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/robots.txt")
    def robots(request: Request):
        host = request.headers.get("host", "")
        return PlainTextResponse("User-agent: *\nAllow: /\n" + (f"Sitemap: https://{host}/sitemap.xml\n" if host else ""))

    @app.get("/sitemap.xml")
    def sitemap(request: Request):
        host = request.headers.get("host", "")
        urls = [("/", POSTS[0]["date"]), ("/archive", POSTS[0]["date"]), ("/about", POSTS[-1]["date"])]
        urls += [(f"/notes/{p['slug']}", p["date"]) for p in POSTS]
        body = "".join(f"<url><loc>https://{host}{u}</loc><lastmod>{d}</lastmod></url>" for u, d in urls)
        xml = ('<?xml version="1.0" encoding="UTF-8"?>'
               '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + body + "</urlset>")
        return Response(xml, media_type="application/xml")
