import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export default async function run(page, ui) {
  const checks = [];
  const consoleErrors = [];
  const pageErrors = [];
  const requestFailures = [];
  const requestProtocols = [];
  const check = (name, condition, detail = null) => {
    if (!condition) throw new Error(`FAIL ${name}${detail ? `: ${JSON.stringify(detail)}` : ''}`);
    checks.push({ name, result: 'PASS', detail });
  };

  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('requestfailed', request => requestFailures.push({ protocol: new URL(request.url()).protocol, error: request.failure()?.errorText || 'unknown' }));
  page.on('request', request => requestProtocols.push(new URL(request.url()).protocol));

  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.reload({ waitUntil: 'load' });
  const snapshot = await ui.snapshot();
  check('controles accesibles presentes', snapshot.includes('Exportar decisión JSON') && snapshot.includes('Solicitar cambios'));
  check('title', (await page.title()) === 'Batch 103 · Revisión G3 — PASS-WITH-NOTES');
  const bodyChars = await page.locator('body').innerText().then(text => text.length);
  check('body renderizado', bodyChars > 8000, { bodyChars });
  const headerText = await page.locator('#resumen').innerText();
  check('cabecera PASS-WITH-NOTES y cero regresiones', await page.locator('[data-gate-status]').innerText() === 'PASS-WITH-NOTES · aceptada con notas' && headerText.includes('0 regresiones reales abiertas') && headerText.includes('Por ahora todo está aprobado. Durante el uso y priebas de usuario espero ver si se sostienen las decisiones tomadas.'));
  check('commit completo', await page.locator('body').innerText().then(text => text.includes('bcc97d2b5a11c74c0ce30655e98684ab55c06307')));
  check('aceptación con notas sin GREEN', await page.locator('body').innerText().then(text => text.includes('no declara full-suite GREEN') && text.includes('listo para promoción')));

  const images = page.locator('img[data-capture]');
  check('ocho capturas', await images.count() === 8);
  const imageState = await images.evaluateAll(items => items.map(img => ({
    complete: img.complete,
    naturalWidth: img.naturalWidth,
    naturalHeight: img.naturalHeight,
    size: img.dataset.size,
    dataUri: img.src.startsWith('data:image/png;base64,')
  })));
  check('imágenes cargadas y embebidas', imageState.every(img => img.complete && img.naturalWidth > 0 && img.naturalHeight > 0 && img.dataUri), imageState);
  check('dimensiones naturales por geometría', imageState.every(img => img.size === '118x54' ? img.naturalWidth === 1111 && img.naturalHeight === 1091 : img.naturalWidth === 2029 && img.naturalHeight === 1205));

  const anchorHrefs = await page.locator('.nav a').evaluateAll(links => links.map(link => link.getAttribute('href')));
  check('siete anchors de navegación', anchorHrefs.length === 7);
  const missingAnchors = await page.evaluate(hrefs => hrefs.filter(href => !document.querySelector(href)), anchorHrefs);
  check('todos los anchors resuelven', missingAnchors.length === 0, { missingAnchors });
  await page.locator('.nav a[href="#incrementos"]').click();
  check('navegación por ancla', await page.evaluate(() => location.hash === '#incrementos'));

  const tabs = page.getByRole('tab');
  check('tres tabs', await tabs.count() === 3);
  await page.getByRole('tab', { name: 'Mutantes' }).click();
  check('tab Mutantes visible', await page.locator('#panel-mutantes').isVisible() && !(await page.locator('#panel-linux').isVisible()));
  check('resultado 71/1/1 visible', await page.locator('#panel-mutantes').innerText().then(text => text.includes('71') && text.includes('GA-A11') && text.includes('GC-C14')));
  await page.getByRole('tab', { name: 'Mutantes' }).press('ArrowRight');
  check('teclado en tabs', await page.locator('#panel-heredados').isVisible());
  await page.getByRole('tab', { name: 'Linux / WinCI' }).click();
  check('métricas WinCI exactas', await page.locator('#panel-linux').innerText().then(text => text.includes('216 passed / 44 skipped') && text.includes('108/108') && text.includes('28/28')));

  const captureDetails = page.locator('details.capture-group');
  check('cuatro grupos de capturas abiertos', await captureDetails.count() === 4 && await captureDetails.evaluateAll(items => items.every(item => item.open)));
  await captureDetails.first().locator('summary').click();
  check('details se cierra', !(await captureDetails.first().evaluate(item => item.open)));
  await captureDetails.first().locator('summary').click();
  check('details se abre', await captureDetails.first().evaluate(item => item.open));

  check('checklist de seis pasos', await page.locator('[data-at-step]').count() === 6);
  for (const checkbox of await page.locator('[data-at-step]').all()) await checkbox.check();
  check('checklist no altera AT', await page.locator('[data-at-status]').innerText() === 'deferred-to-user-validation · not_run · 0/6 ejecutados');
  check('approve habilitado', !(await page.locator('#approve').isDisabled()));
  const blockReason = await page.locator('#approve-reason').innerText();
  check('regla completa clasificada y AT diferida', blockReason.includes('completa y clasificada') && blockReason.includes('0 regresiones abiertas') && blockReason.includes('deferred-to-user-validation / not_run') && blockReason.includes('no se exige como ejecución previa'), { blockReason });

  const desktopOverflow = await page.evaluate(() => ({ scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth }));
  check('sin overflow horizontal desktop', desktopOverflow.scrollWidth <= desktopOverflow.innerWidth, desktopOverflow);
  await page.setViewportSize({ width: 390, height: 844 });
  const mobileOverflow = await page.evaluate(() => ({ scrollWidth: document.documentElement.scrollWidth, innerWidth: window.innerWidth }));
  check('sin overflow horizontal móvil', mobileOverflow.scrollWidth <= mobileOverflow.innerWidth, mobileOverflow);
  check('galería móvil en una columna', await page.locator('.capture-grid').first().evaluate(item => getComputedStyle(item).gridTemplateColumns.split(' ').length === 1));
  await page.setViewportSize({ width: 1440, height: 1100 });

  const note = 'Acepto G3 con notas: full-suite completa clasificada, sin regresiones abiertas; AT-I1b-8 permanece diferida.';
  await page.locator('#approve').check();
  await page.locator('#notes').fill(note);
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#export-json').click();
  const download = await downloadPromise;
  check('nombre de descarga JSON', download.suggestedFilename() === 'g3-decision-bcc97d2b.json');
  const exported = JSON.parse(readFileSync(await download.path(), 'utf8'));
  check('exportación approve real', exported.decision === 'approve' && exported.notes === note, { decision: exported.decision, notes: exported.notes });
  check('JSON conserva notas y diferimiento', exported.gate_status === 'PASS-WITH-NOTES' && exported.operator_decision === 'provisional_approval' && exported.pending.full_suite === 'COMPLETE_CLASSIFIED_RED' && exported.pending.distributed_self_test === 'NOT_RUN' && exported.pending['AT-I1b-8'] === 'deferred-to-user-validation/not_run' && exported.release_authorized === true);
  check('estado de exportación visible', await page.locator('#form-status').innerText().then(text => text.includes('JSON local generado') && text.includes('PASS-WITH-NOTES') && text.includes('listo para promoción')));

  await page.reload({ waitUntil: 'load' });
  check('reload conserva ocho imágenes', await images.count() === 8 && await images.evaluateAll(items => items.every(img => img.complete && img.naturalWidth > 0)));
  check('reload no persiste notas ni checklist', (await page.locator('#notes').inputValue()) === '' && await page.locator('[data-at-step]:checked').count() === 0);
  check('approve sigue habilitado tras reload', !(await page.locator('#approve').isDisabled()));

  await page.emulateMedia({ media: 'print' });
  const printState = await page.evaluate(() => ({
    topbarPosition: getComputedStyle(document.querySelector('.topbar')).position,
    actionsDisplay: getComputedStyle(document.querySelector('.actions')).display,
    hiddenPanelDisplay: getComputedStyle(document.getElementById('panel-mutantes')).display,
    navDisplay: getComputedStyle(document.querySelector('.nav')).display
  }));
  check('print CSS legible y completo', printState.topbarPosition === 'static' && printState.actionsDisplay === 'none' && printState.hiddenPanelDisplay === 'block' && printState.navDisplay === 'none', printState);
  await page.emulateMedia({ media: 'screen' });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: fileURLToPath(new URL('./g3-review-desktop.png', import.meta.url)), fullPage: false });

  check('sin console.error', consoleErrors.length === 0, { consoleErrors });
  check('sin excepciones', pageErrors.length === 0, { pageErrors });
  check('sin requests fallidos', requestFailures.length === 0, { requestFailures });
  check('sin red externa', requestProtocols.every(protocol => protocol === 'file:' || protocol === 'blob:'), { requestProtocols: [...new Set(requestProtocols)] });

  const report = {
    schema: 's19.batch103.g3-browser-verification.v1',
    page: 'g3-review.html',
    commit: 'bcc97d2b5a11c74c0ce30655e98684ab55c06307',
    browser: 'headless browser-automation / patchright',
    result: 'PASS',
    checks,
    console_errors: consoleErrors,
    page_errors: pageErrors,
    request_failures: requestFailures,
    request_protocols: [...new Set(requestProtocols)],
    screenshot: 'g3-review-desktop.png',
    privacy: 'Sin URLs, rutas personales, hosts, IPs ni cuentas en este reporte.'
  };
  writeFileSync(new URL('./verification-report.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
  return { result: report.result, checks: checks.length, bodyChars, images: imageState.length, consoleErrors: consoleErrors.length, pageErrors: pageErrors.length, requestFailures: requestFailures.length, requestProtocols: report.request_protocols, screenshot: report.screenshot };
}
