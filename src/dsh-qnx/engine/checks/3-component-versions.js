// @check component-versions
// Version inventory of image components (kernel, libc, drivers, our stack)
// against the manifest. Checksum drift, missing components, unpinned
// components and (on QNX) components in the boot image the manifest does not
// know about are findings. On QNX, `use -i` prints each binary's embedded
// build info, which is recorded as the component's version.
const findings = [];
const relArgs = ['-r'];
const rel = await tools.uname(relArgs);
const release = rel.stdout.trim();
if (manifest.os_release && release !== manifest.os_release) {
  findings.push({
    id: 'os-release', severity: 'high',
    title: `OS release ${release} differs from manifest (${manifest.os_release})`,
    detail: 'The running kernel is not the one the image declares.',
    evidence: [evidence(rel, 'uname', relArgs)],
    reproduce: { tool: 'uname', args: relArgs, expect: { type: 'not_regex', pattern: `^${manifest.os_release.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, flags: 'm' } },
  });
}

const inventory = [];
for (const c of manifest.components || []) {
  const args = [c.path];
  const r = await tools.cksum(args);
  if (r.exit !== 0) {
    findings.push({
      id: `component-missing-${c.name}`, severity: 'medium',
      title: `Component ${c.name} is missing (${c.path})`,
      detail: 'The manifest declares it; the target does not have it.',
      evidence: [{ receipt: r.receipt, tool: 'cksum', args, excerpt: r.stderr.slice(0, 300) }],
      reproduce: { tool: 'cksum', args, expect: { type: 'regex', pattern: 'No such file|not found|cannot', on: 'stderr' } },
    });
    continue;
  }
  const [crc, size] = r.stdout.trim().split(/\s+/);
  let version = c.version || null;
  if (isQNX) {
    const ui = await tools.use(['-i', c.path]);
    const m = /VERSION=(\S+)/.exec(ui.stdout) || /DATE=(.+)/.exec(ui.stdout);
    if (m) version = m[1];
    if (c.version && !ui.stdout.includes(c.version)) {
      findings.push({
        id: `component-version-${c.name}`, severity: 'medium',
        title: `${c.name}: embedded build info does not mention ${c.version}`,
        detail: 'QNX `use -i` build info disagrees with the manifest version.',
        evidence: [evidence(ui, 'use', ['-i', c.path])],
        reproduce: { tool: 'use', args: ['-i', c.path], expect: { type: 'not_regex', pattern: c.version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') } },
      });
    }
  }
  inventory.push({ name: c.name, path: c.path, cksum: crc, size: Number(size), version });
  if (!c.cksum) {
    findings.push({
      id: `component-unpinned-${c.name}`, severity: 'low',
      title: `Component ${c.name} has no pinned checksum in the manifest`,
      detail: `Observed cksum ${crc} (${size} bytes). Pin it so drift becomes detectable.`,
      evidence: [evidence(r, 'cksum', args)],
      reproduce: { tool: 'cksum', args, expect: { type: 'regex', pattern: '^\\d+ \\d+ ' } },
    });
  } else if (String(c.cksum) !== crc) {
    findings.push({
      id: `component-drift-${c.name}`, severity: 'high',
      title: `Component ${c.name} changed: cksum ${crc}, manifest says ${c.cksum}`,
      detail: `${c.path} on the target is not the binary the image shipped.`,
      evidence: [evidence(r, 'cksum', args)],
      reproduce: { tool: 'cksum', args, expect: { type: 'not_regex', pattern: `^${c.cksum} ` } },
    });
  }
}

if (isQNX) {
  const bootArgs = ['/proc/boot'];
  const boot = await tools.ls(bootArgs);
  const known = new Set((manifest.components || []).map((c) => c.path.replace(/^.*\//, '')));
  const extra = (manifest.boot_image_allow || []);
  for (const n of parse.lines(boot.stdout).map((x) => x.trim())) {
    if (known.has(n) || matchesAny(n, extra)) continue;
    findings.push({
      id: `boot-unversioned-${n}`, severity: 'low',
      title: `/proc/boot/${n} is in the boot image but not in the manifest`,
      detail: 'Unversioned component: nothing pins what this binary should be.',
      evidence: [evidence(boot, 'ls', bootArgs, n)],
      reproduce: { tool: 'ls', args: bootArgs, expect: { type: 'regex', pattern: `^${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, flags: 'm' } },
    });
  }
}
return {
  check: 'component-versions',
  summary: { release, components: inventory, receipt: rel.receipt },
  findings: capFindings(findings, 'component-versions'),
};
