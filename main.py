from pathlib import Path
import yaml
import datetime

def define_env(env):
    @env.macro
    def get_blog_posts():
        posts = []
        blog_dir = Path(env.variables['config']['docs_dir']) / "blog/posts"

        for md_file in blog_dir.glob("*.md"):
            with open(md_file, "r", encoding="utf-8") as f:
                lines = f.read()

            if lines.startswith("---"):
                _, fm, content = lines.split('---', 2)
                meta = yaml.safe_load(fm)
                meta['url'] = "blog/" + meta['slug']
                meta['content'] = content
                meta['date_obj'] = datetime.datetime.strftime(datetime.datetime.strptime(str(meta['date']), '%Y-%m-%d'), '%B %d, %Y')
                posts.append(meta)

        # Sort newest first
        return sorted(posts, key=lambda x: x['date_obj'], reverse=True)
