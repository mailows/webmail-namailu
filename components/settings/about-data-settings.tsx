"use client";

import { useState, useRef } from 'react';
import { useTranslations } from 'next-intl';
import { useSettingsStore } from '@/stores/settings-store';
import { useConfig } from '@/hooks/use-config';
import { SettingsSection, SettingItem, ToggleSwitch } from './settings-section';
import { Button } from '@/components/ui/button';
import { usePolicyStore } from '@/stores/policy-store';
import { clearCachedData } from '@/lib/clear-cached-data';

export function AboutDataSettings() {
  const t = useTranslations('settings.advanced');
  const tCommon = useTranslations('common');
  const tSettings = useTranslations('settings');
  const { settingsSyncDisabled, updateSetting, resetToDefaults, exportSettings, importSettings } =
    useSettingsStore();
  const { settingsSyncEnabled } = useConfig();
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [showRefreshConfirm, setShowRefreshConfirm] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { isFeatureEnabled } = usePolicyStore();
  const handleExport = () => {
    const settingsJson = exportSettings();
    const blob = new Blob([settingsJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `webmail-settings-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleImport = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const json = event.target?.result as string;
      const success = importSettings(json);
      if (success) {
        alert(tSettings('import_success'));
      } else {
        alert(tSettings('import_error'));
      }
    };
    reader.readAsText(file);
  };

  const handleRefreshCache = () => {
    if (showRefreshConfirm) {
      clearCachedData(); // reloads the page
    } else {
      setShowRefreshConfirm(true);
      setTimeout(() => setShowRefreshConfirm(false), 5000);
    }
  };

  const handleReset = () => {
    if (showResetConfirm) {
      resetToDefaults();
      setShowResetConfirm(false);
      alert(tSettings('save_success'));
    } else {
      setShowResetConfirm(true);
      setTimeout(() => setShowResetConfirm(false), 5000);
    }
  };

  return (
    <>
      {/* FORK: celý „about" banner je pryč — logo a jméno upstreamu, verze i odkaz na
          zdrojový kód. Nabídka zdroje podle AGPL-3.0 §13 se přesouvá na právní statement
          mimo aplikaci (rozhodnutí 30. 7. 2026); do spuštění tam MUSÍ být, jinak fork
          nabízíme bez nabídky zdroje. Viz webmail/FORK.md.

          Verze a commit tím zmizely z UI; pro provoz je vidíme na image tagu a v adminu.
          Se bannerem odešel i easter egg (hra se spouštěla klikem na logo). */}
      <SettingsSection title={t('title')} description={t('description')}>
        {settingsSyncEnabled && (
          <SettingItem label={t('settings_sync.label')} description={t('settings_sync.description')}>
            <ToggleSwitch checked={!settingsSyncDisabled} onChange={(checked) => updateSetting('settingsSyncDisabled', !checked)} />
          </SettingItem>
        )}

        {isFeatureEnabled('settingsExportEnabled') && (
        <SettingItem label={t('export_settings.label')} description={t('export_settings.description')}>
          <Button variant="outline" size="sm" onClick={handleExport}>
            {t('export_settings.button')}
          </Button>
        </SettingItem>
        )}

        {isFeatureEnabled('settingsExportEnabled') && (
        <SettingItem label={t('import_settings.label')} description={t('import_settings.description')}>
          <>
            <input
              ref={fileInputRef}
              type="file"
              accept="application/json,.json"
              onChange={handleFileChange}
              className="hidden"
            />
            <Button variant="outline" size="sm" onClick={handleImport}>
              {t('import_settings.button')}
            </Button>
          </>
        </SettingItem>
        )}

        <SettingItem label={t('refresh_cache.label')} description={t('refresh_cache.description')}>
          <Button
            variant={showRefreshConfirm ? 'default' : 'outline'}
            size="sm"
            onClick={handleRefreshCache}
          >
            {showRefreshConfirm ? tCommon('yes') : t('refresh_cache.button')}
          </Button>
        </SettingItem>

        <SettingItem label={t('reset_settings.label')} description={t('reset_settings.description')}>
          <Button
            variant={showResetConfirm ? 'destructive' : 'outline'}
            size="sm"
            onClick={handleReset}
          >
            {showResetConfirm ? tCommon('yes') : t('reset_settings.button')}
          </Button>
        </SettingItem>
      </SettingsSection>
    </>
  );
}
