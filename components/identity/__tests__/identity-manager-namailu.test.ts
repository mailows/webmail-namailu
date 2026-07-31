import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * namailu.cz spravuje adresy, aliasy a schránky v portálu. Webmail smí upravit
 * pouze existující profil odesílatele; obecný upstreamový Identity/set create
 * formulář byl matoucí a pro nepřiřazenou adresu jej Stalwart stejně odmítl.
 */
describe('Identity manager — jediný existující profil', () => {
  const manager = readFileSync(
    resolve(process.cwd(), 'components/identity/identity-manager-modal.tsx'),
    'utf-8',
  );
  const settings = readFileSync(
    resolve(process.cwd(), 'components/settings/identity-settings.tsx'),
    'utf-8',
  );

  it('nenabízí vytvoření ani odstranění identity', () => {
    expect(manager).not.toContain('createIdentity(');
    expect(manager).not.toContain('deleteIdentity(');
    expect(manager).not.toContain("t('create_new')");
  });

  it('otevře rovnou editaci aktuální identity', () => {
    expect(manager).toContain('identity={identities[0]}');
    expect(manager).toContain('client.updateIdentity(');
    expect(settings).toContain('currentIdentity?.email');
  });

  it('subadresování neotevírá editor identity', () => {
    expect(settings).toContain("label={t('sub_addressing.label')}");
    expect(settings).not.toContain("t('sub_addressing.learn_more')");
  });
});
