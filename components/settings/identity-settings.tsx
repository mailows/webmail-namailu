'use client';

import { useState } from 'react';
import { useTranslations } from 'next-intl';
import { Button } from '@/components/ui/button';
import { SettingsSection, SettingItem } from './settings-section';
import { IdentityManagerModal } from '@/components/identity/identity-manager-modal';
import { useIdentityStore } from '@/stores/identity-store';

export function IdentitySettings() {
  const t = useTranslations('settings.identities');
  const { identities } = useIdentityStore();
  const currentIdentity = identities[0];
  const [showModal, setShowModal] = useState(false);

  return (
    <>
      <SettingsSection title={t('title')} description={t('description')}>
        <SettingItem
          label={t('identities_count.label')}
          description={t('identities_count.description')}
        >
          <div className="flex items-center gap-2">
            <span className="text-sm text-foreground">
              {currentIdentity?.email ?? t('identities_count.count_zero')}
            </span>
            <Button
              onClick={() => setShowModal(true)}
              size="sm"
              disabled={!currentIdentity}
            >
              {t('manage')}
            </Button>
          </div>
        </SettingItem>

        {/* Sub-Addressing Info */}
        <SettingItem
          label={t('sub_addressing.label')}
          description={t('sub_addressing.description')}
        >
          {null}
        </SettingItem>
      </SettingsSection>

      {/* Identity Manager Modal */}
      <IdentityManagerModal
        isOpen={showModal}
        onClose={() => setShowModal(false)}
      />
    </>
  );
}
