import asyncio,json,inspect,importlib.metadata
from pathlib import Path
from harbor.registry.client.factory import RegistryClientFactory
root=Path('/workspaces/exp/benign-utility/raw/benchmark')
async def main():
 c=RegistryClientFactory.create()
 m=await c.get_dataset_metadata('terminal-bench@2.0')
 (root/'registry-metadata.json').write_text(m.model_dump_json(indent=2))
 print('harbor',importlib.metadata.version('harbor'))
 for t in m.task_ids[:3]: print(t)
 print('task_count',len(m.task_ids))
asyncio.run(main())
