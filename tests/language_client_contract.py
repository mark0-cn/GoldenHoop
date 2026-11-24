"""All advertised languages through Python sync/async and the Rust CLI."""
import os
from uuid import uuid4
from goldenhoop import CodeContextSpec, CodeRunSpec
from language_samples import LANGUAGES, SAMPLES


def first_output_ok(text):
    # Compiler diagnostics remain visible in the collected output.
    return text.endswith('kernel-start\n') and text.count('kernel-start\n')==1


def observed_languages(profiles):
    profile = next(p for p in profiles if p['id']==os.environ['GOLDENHOOP_TEST_PROFILE'])
    expected=set(os.environ.get('GOLDENHOOP_TEST_CODE_LANGUAGES','python').split(','))
    assert set(profile['code_languages'])==expected, profile
    return [language for language in LANGUAGES if language in expected]


def sync_bindings(client,sandbox):
    languages=observed_languages(client.profiles())
    for language in languages:
        spec=CodeContextSpec(language=language)
        key=str(uuid4())
        context=client.create_code_context(sandbox,spec,key)['id']
        assert client.create_code_context(sandbox,spec,key)['id']==context
        ready=client.wait_code_context_ready(context)
        assert ready['spec']['language']==language and ready['kernel_info']['language_info']['name']==language
        first,second,error=SAMPLES[language]
        key=str(uuid4())
        result=client.run_code(context,CodeRunSpec(first,timeout_seconds=30),key)
        replay=client.run_code(context,CodeRunSpec(first,timeout_seconds=30),key)
        assert result.run['id']==replay.run['id'] and result.stdout==replay.stdout and first_output_ok(replay.stdout)
        assert client.read_file(sandbox,'lang-replay-'+language)==b'x'
        assert client.run_code(context,CodeRunSpec(second)).stdout=='42\n'
        assert client.run_code(context,CodeRunSpec(error)).run['state']=='kernel_failed'
        client.close_code_context(context,str(uuid4()))
        assert client.wait_code_context_closed(context)['cleanup']=='complete'
    return languages


async def async_bindings(client,sandbox):
    languages=observed_languages(await client.profiles())
    for language in languages:
        spec=CodeContextSpec(language=language)
        key=str(uuid4())
        context=(await client.create_code_context(sandbox,spec,key))['id']
        assert (await client.create_code_context(sandbox,spec,key))['id']==context
        ready=await client.wait_code_context_ready(context)
        assert ready['spec']['language']==language and ready['kernel_info']['language_info']['name']==language
        first,second,error=SAMPLES[language]
        key=str(uuid4())
        result=await client.run_code(context,CodeRunSpec(first,timeout_seconds=30),key)
        replay=await client.run_code(context,CodeRunSpec(first,timeout_seconds=30),key)
        assert result.run['id']==replay.run['id'] and result.stdout==replay.stdout and first_output_ok(replay.stdout)
        assert await client.read_file(sandbox,'lang-replay-'+language)==b'x'
        assert (await client.run_code(context,CodeRunSpec(second))).stdout=='42\n'
        assert (await client.run_code(context,CodeRunSpec(error))).run['state']=='kernel_failed'
        await client.close_code_context(context,str(uuid4()))
        assert (await client.wait_code_context_closed(context))['cleanup']=='complete'
    return languages


def cli_bindings(invoke,observer,sandbox):
    languages=observed_languages(observer.profiles())
    for language in languages:
        key=str(uuid4())
        context=invoke('context-create',sandbox,'--language',language,'--idempotency-key',key)['id']
        assert invoke('context-create',sandbox,'--language',language,'--idempotency-key',key)['id']==context
        ready=invoke('context-get',context)
        assert ready['spec']['language']==language and ready['kernel_info']['language_info']['name']==language
        first,second,error=SAMPLES[language]
        key=str(uuid4())
        result=invoke('code-run',context,'-','--timeout','30','--idempotency-key',key,source=first)
        replay=invoke('code-run',context,'-','--timeout','30','--idempotency-key',key,source=first)
        assert result['run']['id']==replay['run']['id'] and result['stdout']==replay['stdout'] and first_output_ok(replay['stdout'])
        assert observer.read_file(sandbox,'lang-replay-'+language)==b'x'
        assert invoke('code-run',context,'-',source=second)['stdout']=='42\n'
        assert invoke('code-run',context,'-',source=error,expected=1)['run']['state']=='kernel_failed'
        assert invoke('context-close',context)['cleanup']=='complete'
    return languages
