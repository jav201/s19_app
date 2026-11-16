#!/bin/bash
# F8 battery: 14 Inc 8 files + laws on clone8; the scratch merge into b103-inc10 and its 8 nodes.
cd ~/work/zq-f8 || exit 9
for f in $(cd clone8 && ls tests/test_b103_inc8_*.py); do
  b=$(basename $f .py); ./run.sh clone8 bat-$b.txt -n 2 $f
done
./run.sh clone8 bat-laws.txt -n 2 tests/test_docs_canon.py tests/test_b101_doc_hygiene.py tests/test_b101_help_legend_docs.py tests/test_no_private_tokens.py tests/test_filename_markup_safety.py tests/test_report_markup_safety.py tests/test_id_registry.py tests/test_deps_seam_law.py tests/test_engine_unchanged.py tests/test_requirements_canon.py
./run.sh clone8 bat-laws-tc031.txt -n 2 tests/test_tui_directionb.py -k tc031
# scratch merge (never a worktree)
rm -rf merge10 && git clone -q -b b103-inc10 f8.bundle merge10 && cd merge10 && git branch -q b103-inc8 origin/b103-inc8 \
  && git -c user.name=f8 -c user.email=f8@localhost merge --no-ff -q -m "scratch merge b103-inc8 into b103-inc10" b103-inc8 > ../merge.txt 2>&1; echo "MERGE_RC=$?" >> ../merge.txt
git log --oneline -1 >> ../merge.txt; git status --short | head >> ../merge.txt
cd ..
./run.sh merge10 m10-b100.txt -n 2 tests/test_b100_active_variant.py -k "not tc_b100" -v
./run.sh merge10 m10-b99.txt -n 2 tests/test_b99_editor_image.py -v
./run.sh merge10 m10-b99s0.txt -n 2 tests/test_b99_s0.py -k at_b99_02 -v
# test-side fix demo on a copy: scroll the target into view before each selector click (Inc 8's click_visible idiom)
rm -rf merge10fix && cp -r merge10 merge10fix && cat >> merge10fix/tests/conftest.py <<'PY'


# F8 scratch only (never committed): Inc 8's click_visible idiom for every selector click.
import textual.pilot as _f8_pilot

_f8_click_orig = _f8_pilot.Pilot.click


async def _f8_click(self, widget=None, *args, **kwargs):
    if isinstance(widget, str):
        self.app.screen.query_one(widget).scroll_visible(animate=False)
        await self.pause()
    return await _f8_click_orig(self, widget, *args, **kwargs)


_f8_pilot.Pilot.click = _f8_click
PY
./run.sh merge10fix m10fix-b100.txt -n 2 tests/test_b100_active_variant.py -k "not tc_b100" -v
./run.sh merge10fix m10fix-b99.txt -n 2 tests/test_b99_editor_image.py -v
./run.sh merge10fix m10fix-b99s0.txt -n 2 tests/test_b99_s0.py -k at_b99_02 -v
echo BATTERY_DONE > battery.done
