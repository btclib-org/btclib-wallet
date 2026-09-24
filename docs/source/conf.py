# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Configuration file for the Sphinx documentation builder.

For the full list of built-in configuration values, see the
documentation:
https://www.sphinx-doc.org/en/master/usage/configuration.html
"""

import re
import tomllib
from pathlib import Path
from typing import Any

from docutils import nodes
from sphinx.addnodes import pending_xref
from sphinx.application import Sphinx
from sphinx.transforms.post_transforms import SphinxPostTransform

# the repository root, two levels up from this file, and the one place
# below that is allowed to name it
ROOT = Path(__file__).parents[2].resolve()
# read once, for the author and version below and the github url the
# transform at the bottom builds its links on
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = PYPROJECT["project"]["name"]
# pyproject.toml's `authors` table, the one place the holder is
# declared: PYPROJECT is already parsed above, so this is a second read
# of it rather than a second literal
author = PYPROJECT["project"]["authors"][0]["name"]
# the holder the MIT notice names, which is that same author, and no year:
# COPYRIGHT and LICENSE state none, a year being a thing that looks out of
# date every January without anything having changed
project_copyright = author
# read from pyproject.toml, the one place the version is declared, and not
# from importlib.metadata: the value should not depend on whether the
# package happens to be installed in the environment building the
# documentation (btclib-org/.github#1098)
release = PYPROJECT["project"]["version"]

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    # first, because -n below turns an unresolved cross-reference into a
    # warning and the annotations of this package name what the standard
    # library, btclib and bitcoin-core-rpc own: without an inventory to
    # resolve against, `pathlib.Path` and `btclib.tx.Tx` are reported as
    # this tree's own broken links and the triage measures sphinx's
    # ignorance rather than the documentation
    "sphinx.ext.intersphinx",
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

# no sphinx.ext.todo: with todo_include_todos left at its default a
# `.. todo::` renders as nothing at all, so the directive is a note to
# nobody. Without the extension it is an unknown directive, which -W turns
# into a failed build -- the open questions belong in the issue tracker

# the standard library, and the two siblings this package depends on,
# whose types its signatures name. `latest` for both, being the build of
# each sibling's main: a name a sibling removed is the break a build here
# should report
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "btclib": ("https://btclib.readthedocs.io/en/latest/", None),
    "bitcoin_core_rpc": (
        "https://bitcoin-core-rpc.readthedocs.io/en/latest/",
        None,
    ),
}
# no reuse of a fetched inventory: sphinx keeps one for as many days as
# this allows, invisibly to a diff and even under -E, and a sibling's
# `latest` moves on this organization's own landings, so a name it removed
# would still resolve on a checkout and fail on a runner. Section 2 of the
# organization's standard asks for 0 where a mapping names a sibling
intersphinx_cache_limit = 0

# What the mapping above does not answer for is two shapes, neither an
# inventory can fix, and each entry below carries its own reason rather
# than a nitpick_ignore_regex that would give the check up entirely:
#
# - a name an annotation spells the way the module imported it --
#   `Octets` from btclib.alias, `musig2.` for btclib.ecc.musig2 -- which
#   btclib's own build resolves by searching its own objects, where an
#   inventory answers the full name alone. autodoc_type_aliases is the
#   rejected alternative: mapping `Octets` to its full name renders a
#   class reference to what btclib's inventory lists as data, and every
#   signature carrying it fails in its place
# - a subscripted generic written inline in a signature, where sphinx's
#   own type-to-xref splitter stops at the first nested bracket and
#   reports the truncated fragment as the unresolved class, rather than
#   resolving the pieces on either side of it
nitpick_ignore = [
    ("py:class", "Octets"),
    ("py:class", "musig2.KeyAggContext"),
    ("py:class", "musig2.SessionContext"),
    ("py:class", "collections.abc.Mapping[bytes"),
]

source_suffix = [".rst", ".md"]

# anchors for h1 to h6, which is what makes a link into a heading of a
# root markdown file resolve here. Without it myst generates no anchor at
# all, so a link GitHub and PyPI both follow, the anchor being what those
# two derive from the heading text, becomes an xref to a target no page
# has, and -W fails the build. Six is every level markdown heads at,
# which makes the number a fixed point rather than one re-derived from
# files that move: section 2 of the organization standard says so, and
# names a depth read off this tree's own headings as the rejected
# alternative. Part of what such a
# re-derivation would read is not this tree's to hold still either --
# section 14 ports CONTRIBUTING.md's shared half into every repository,
# so a heading added there moves the depth in each of them at once
myst_heading_anchors = 6

# no suppress_warnings, and myst.xref_missing least of all: the transform
# at the bottom of this file resolves every link the included root files
# carry, so a myst target still missing is a link with nowhere to go and
# -W is what says so. Suppressing that subtype hides the defect rather than
# the noise, because what myst emits for a target it cannot resolve is not
# a visibly broken link, it is an anchor to an id the page does not have

exclude_patterns: list[str] = []


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# furo: content first, the navigation in the left sidebar and the page's
# own contents in the right, light and dark from one setting -- the shape
# a reference generated from docstrings has. Section 2 of the organization
# standard is where it was weighed against shibuya, whose landing pages
# and announcement bars are surface this tree would carry and not use;
# sphinx_rtd_theme is where a Read the Docs project starts by default,
# which is a reason to find it in a tree rather than to keep it
html_theme = "furo"

# no html_static_path: this project overrides no stylesheet and ships no
# image, so the "_static" the sphinx template declares names a directory
# that does not exist, and sphinx warns about it on every build, which -W
# turns into a failure. The setting arrives with the directory, not before
# it


# -- Links out of the included root markdown files ----------------------------

# Some pages of the toctree are this repository's root markdown files --
# README, CONTRIBUTING, REVIEWING, SECURITY, RELEASE_NOTES and CHANGELOG
# -- each pulled into a *_link.md shim by a myst {include}. The
# shims are what the code below reads, so adding one needs no edit here.
# Those files are written for the two places that read them unrendered --
# the GitHub file view and the PyPI long description -- so
# "./SECURITY.md" is the correct spelling there and the one links.yml
# checks, resolving it as a path relative to the file. Sphinx sees them
# lifted out of the tree that makes it correct, and myst resolves not one
# of those links.
#
# What it emits instead is the reason this needs code rather than a
# warning filter: a target myst cannot resolve becomes an anchor on the
# page it is already on, href="#./SECURITY.md", an id nothing has. The
# build succeeds, -W sees nothing, and lychee reads the sources, where the
# path is right.
#
# The transform below answers each link from the repository rather than
# from a table that would have to be kept in step with this directory: a
# path a *_link.md shim includes becomes a reference to that page, any
# other path that exists in the tree becomes a link to the file on GitHub,
# and a path that exists nowhere is left to myst -- which reports it, and
# -W then fails, now that suppress_warnings no longer hides the subtype.
#
# It also reads a link written this way *outside* a shim, resolved
# against the document that wrote it rather than against ROOT. A page
# under docs/source is itself read unrendered on the forge, so a link
# composed relative to its own file -- "../../README.md#installing",
# climbing out of docs/source the way a checkout resolves it -- works
# there verbatim, and this is what lets the same link resolve here too,
# through the shim page that carries the heading once the {include} has
# run.
#
# Not the {include} directive's :relative-docs: option, which is what it
# looks like the job of. It rewrites destinations that begin with the
# prefix it is given, so "docs/source/" leaves "./SECURITY.md" untouched;
# and giving it "./" is worse than doing nothing, measured -- the
# destination becomes "../../SECURITY.md", a path outside srcdir that is
# no document, sphinx reads it as a download, finds nothing to copy, and
# renders the link text with no link at all.
#
# Not copying the root files into this directory at build time either.
# README.md links to LICENSE, which is not part of the documentation --
# no shim includes it, which is what decides it -- so copies leave that
# link dead however many are made; and the copies are generated files in
# a source tree, which is a second definition of files that already
# exist.

# a shim is one myst include fence, and everything after the directive
# name on that line is the directive's argument: the path of the file the
# shim renders, spaces included. Options are the lines under it, never
# this one, so the path ends where the line does
INCLUDE = re.compile(r"^```\{include\}\s+(.+?)\s*$", re.MULTILINE)


def included(shim: Path) -> tuple[str, str]:
    """Map the file a *_link.md shim renders to the shim's own docname."""
    # exactly one fence, and a shim with any other number stops the build
    # here rather than going missing from the mapping. Missing is the one
    # failure this file cannot report on itself: links *out* of that page
    # would be left to myst, which reports them, but links *into* it from
    # the other shims would still resolve -- to the copy on github, next to
    # the page that renders it and silently not it
    paths = INCLUDE.findall(shim.read_text(encoding="utf-8"))
    if len(paths) != 1:
        err_msg = f"{shim.name}: {len(paths)} include fences, expected one"
        raise ValueError(err_msg)
    return str((shim.parent / paths[0]).resolve().relative_to(ROOT)), shim.stem


# repository-relative path -> the docname whose page renders it
INCLUDED = dict(map(included, sorted(Path(__file__).parent.glob("*_link.md"))))
# main, not a permalink pinned to a commit: these are navigation links
# to files that keep changing, and a reader following one wants the file
# as it stands. The base url comes from pyproject.toml, where every url
# this project publishes is declared
BLOB = f"{PYPROJECT['project']['urls']['repository']}/blob/main/"


class RootFileLinks(SphinxPostTransform):
    """Resolve the repository-relative links naming a file of this tree."""

    # ahead of myst's own resolver, which runs at 9 and is what turns an
    # unresolved target into that anchor
    default_priority = 5

    def _broken_doc_target(self, node: pending_xref) -> tuple[Path, str | None] | None:
        """Recover the file behind a "doc" xref `path2doc` resolved wrong.

        myst already thinks this resolves; a real docname is a working
        cross-reference and none of this file's business. Anything else is
        `Project.path2doc` stripping a matching suffix off *any* file that
        exists on disk, docs or not (sphinx/project.py), so a link climbing
        out of srcdir into a real file -- a page under docs/source
        linking into README.md -- reads as resolved when it is not.
        Recover the file it actually named: reftarget is that path with
        its suffix gone, and only one of the two the tree parses still
        fits.
        """
        if node["reftarget"] in self.env.all_docs:
            return None
        candidates = (Path(f"{node['reftarget']}{suffix}") for suffix in source_suffix)
        found = next((c for c in candidates if c.is_file()), None)
        return None if found is None else (found, node.get("reftargetid"))

    def _unbound_target(
        self, node: pending_xref, refdoc: str
    ) -> tuple[Path, str | None]:
        """Resolve a link myst left with no domain at all.

        A shim's own included content is written relative to the root
        file it renders, which sits at ROOT itself; any other document is
        written relative to wherever it actually sits in the source tree
        -- doc2path is what answers that without assuming every docname
        sits flat under docs/source.
        """
        raw, _, anchor = node["reftarget"].partition("#")
        origin = (
            ROOT
            if refdoc in INCLUDED.values()
            else Path(self.env.doc2path(refdoc)).parent
        )
        return origin / raw, anchor or None

    def run(self, **kwargs: Any) -> None:
        """Rewrite every myst xref naming a file of this repository."""
        # the list is taken before the tree is edited: replace_self on a
        # node the generator is standing on reparents its children under it
        for node in list(self.document.findall(pending_xref)):
            if node.get("reftype") != "myst":
                continue
            refdomain = node.get("refdomain")
            if refdomain == "doc":
                resolved = self._broken_doc_target(node)
            elif refdomain is None:
                refdoc = node.get("refdoc", self.env.docname)
                resolved = self._unbound_target(node, refdoc)
            else:
                resolved = None
            if resolved is None:
                continue
            found, anchor = resolved
            try:
                # "./tests/README.md" from a shim resolves to
                # "tests/README.md"; a page's own "../../README.md"
                # resolves to "README.md" the same way, against the real
                # filesystem, so a path climbing above ROOT raises rather
                # than reading as one of its own
                target = str(found.resolve().relative_to(ROOT))
            except ValueError:
                # outside the repository: nothing this can answer
                continue
            if target in INCLUDED:
                # handed back to myst as the link it would have been
                # written as, so the page title and the caption are its
                # business and not this file's
                node["refdomain"] = "doc"
                node["reftarget"] = INCLUDED[target]
                node["reftargetid"] = anchor or None
            elif (ROOT / target).is_file():
                fragment = f"#{anchor}" if anchor else ""
                reference = nodes.reference(
                    "", "", refuri=f"{BLOB}{target}{fragment}", internal=False
                )
                reference.extend(node.children)
                node.replace_self(reference)


def setup(app: Sphinx) -> None:
    """Register the transform above; sphinx calls this."""
    app.add_post_transform(RootFileLinks)
