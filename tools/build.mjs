// src/ 의 사이트를 비밀번호로 암호화해서 배포용 index.html 하나로 만든다.
//
//   PowerShell:  $env:PREP_PASSWORD='비밀번호'; node tools/build.mjs
//   Git Bash:    PREP_PASSWORD='비밀번호' node tools/build.mjs
//
// - src/ 는 .gitignore 되어 GitHub에 올라가지 않는다 (원본은 이 컴퓨터에만 있음).
// - 암호화: PBKDF2-SHA256(비밀번호, salt, ITERATIONS) → AES-256-GCM
// - salt 는 src/.salt 에 한 번 만들어 재사용한다. 비밀번호가 같으면 태블릿에 기억된 키가 다음 배포에도 그대로 동작한다.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes, webcrypto } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src');
const ITERATIONS = 1_000_000;
const { subtle } = webcrypto;

const password = process.env.PREP_PASSWORD;
if (!password) {
  console.error('PREP_PASSWORD 환경변수에 비밀번호를 넣고 실행하세요.');
  process.exit(1);
}

const read = p => readFileSync(join(SRC, p), 'utf8');
const index = read('index.html');
const body = index.match(/<body>([\s\S]*?)<script/)[1];
const scriptSrcs = [...index.matchAll(/<script src="([^"]+)"><\/script>/g)].map(m => m[1])
  .filter(p => existsSync(join(SRC, p)) || (console.warn('건너뜀(파일 없음):', p), false))
  // 검증이 끝나지 않은 파일은 PREP_EXCLUDE="js/a.js,js/b.js" 로 빼고 빌드할 수 있다
  .filter(p => !(process.env.PREP_EXCLUDE || '').split(',').includes(p) || (console.warn('제외(검증 대기):', p), false));
const js = scriptSrcs.map(p => `/* ${p} */\n` + read(p));
const css = read('css/style.css');
const site = JSON.stringify({ v: 1, builtAt: new Date().toISOString(), css, body, js });

const saltFile = join(SRC, '.salt');
if (!existsSync(saltFile)) writeFileSync(saltFile, randomBytes(16).toString('base64'));
const saltB64 = readFileSync(saltFile, 'utf8').trim();
const salt = Buffer.from(saltB64, 'base64');
const iv = randomBytes(12);

const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(site)));

const payload = JSON.stringify({ salt: saltB64, iv: iv.toString('base64'), iter: ITERATIONS, data: ct.toString('base64') });
const loader = readFileSync(join(ROOT, 'tools', 'loader.html'), 'utf8');
writeFileSync(join(ROOT, 'index.html'), loader.replace('__PAYLOAD__', payload));

console.log(`index.html 생성: 스크립트 ${js.length}개, 원본 ${(site.length / 1024).toFixed(0)}KB → 암호문 ${(ct.length / 1024).toFixed(0)}KB`);
