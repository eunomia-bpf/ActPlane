#!/usr/bin/env python3
"""Record uncached list-price equivalents, not subscription bills or GPU costs."""
from prepare import HERE, csv_write


def main():
    zai = 'https://docs.z.ai/guides/overview/pricing'
    claude = 'https://platform.claude.com/docs/en/about-claude/pricing'
    rows = []
    for model, inp, out, source, basis in [
        ('qwen3.8-27b-nvfp4', '', '', '', 'local infrastructure cost not measured'),
        ('zai/glm-5.3', 1.4, 4.4, zai, 'uncached list price equivalent'),
        ('zai/glm-5.3-flash', .15, .50, zai, 'uncached list price equivalent'),
        ('zai/glm-4.7-flash', 0, 0, zai, 'free public API list price'),
        ('zai/glm-4.5-air', .2, 1.1, zai, 'uncached list price equivalent'),
        ('claude-opus-4-6', 5, 25, claude, 'uncached API equivalent; subscription CLI used'),
    ]:
        rows.append(dict(model=model, input_usd_per_million=inp, output_usd_per_million=out,
                         source=source, verified_utc='2026-10-28', basis=basis))
    csv_write(HERE / 'prices.csv', rows)


if __name__ == '__main__':
    main()
