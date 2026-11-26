# Email archive

A static, searchable inbox with sender autocomplete, sidebar labels, date filters,
attachment downloads, and export of filtered messages. The generated `index.html`
already contains the email data. Deployment needs no MBOX, API key, or backend.

Publishing this site makes the included emails and attachments available to site
visitors. The inbox has no login or access controls.

## Deploy with GitHub Actions

1. Commit and push this repository, including `.github/workflows/deploy-pages.yml`.
2. In the GitHub repository, open **Settings → Pages → Build and deployment**.
3. Set **Source** to **GitHub Actions**.
4. Open **Actions → Deploy email archive to GitHub Pages** and click **Run workflow**
   for the first deployment after enabling Pages. Later pushes to `main` deploy
   automatically.
5. Open the website URL shown by the deployment. For a project repository, the URL
   is normally `https://YOUR-USERNAME.github.io/YOUR-REPOSITORY/`.

The workflow publishes only `index.html`, `All Emails.txt`, the `attachments/`
folder, and a `.nojekyll` marker. It validates every attachment's size and checksum
before deploying. It excludes source code, Git metadata, caches, and original MBOX
files from the website. Relative links support GitHub Pages repository URLs.

Use GitHub Desktop or `git push` to upload the repository. One attachment exceeds
GitHub's browser-upload limit of 25 MB; all current files are below the 100 MiB
limit for regular Git uploads.

## Preview locally

From this repository's root, run:

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

Open `http://127.0.0.1:8080/`. You can also open `index.html` directly in a browser.

Read status and stars are saved in each visitor's browser. They do not sync between
the local copy and the published website.
