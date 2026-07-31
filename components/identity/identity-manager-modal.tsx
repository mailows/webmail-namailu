'use client';

import { useEffect, useCallback } from 'react';
import { useTranslations } from 'next-intl';
import { X, Mail } from 'lucide-react';
import { cn } from '@/lib/utils';
import { IdentityForm } from './identity-form';
import { useIdentityStore } from '@/stores/identity-store';
import { useAuthStore } from '@/stores/auth-store';
import type { Identity, EmailAddress } from '@/lib/jmap/types';
import { toast } from '@/stores/toast-store';
import { useFocusTrap } from '@/hooks/use-focus-trap';

function emailMatchesUsername(email: string, username: string): boolean {
  if (email === username) return true;
  if (!username.includes('@') && email.split('@')[0] === username) return true;
  return false;
}

interface IdentityFormData {
  name: string;
  email: string;
  replyTo?: EmailAddress[] | null;
  bcc?: EmailAddress[] | null;
  textSignature?: string | null;
  htmlSignature?: string | null;
}

interface IdentityManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function IdentityManagerModal({ isOpen, onClose }: IdentityManagerModalProps) {
  const t = useTranslations('identities');
  const tNotif = useTranslations('notifications');

  const client = useAuthStore((state) => state.client);
  const identities = useIdentityStore((state) => state.identities);
  const syncIdentities = useAuthStore((state) => state.syncIdentities);

  // Re-fetch all identities from server and update stores
  const refreshIdentities = useCallback(async () => {
    if (!client) return;
    try {
      const serverIdentities = await client.getIdentities();
      const username = useAuthStore.getState().username;
      const preferredPrimaryId = useIdentityStore.getState().preferredPrimaryId;
      const sorted = [...serverIdentities].sort((a, b) => {
        const aMatch = emailMatchesUsername(a.email, username || '');
        const bMatch = emailMatchesUsername(b.email, username || '');
        if (aMatch && !bMatch) return -1;
        if (!aMatch && bMatch) return 1;
        if (aMatch && bMatch) {
          if (!a.mayDelete && b.mayDelete) return -1;
          if (a.mayDelete && !b.mayDelete) return 1;
        }
        return 0;
      });
      // Move preferred primary to front if set
      if (preferredPrimaryId) {
        const idx = sorted.findIndex((id) => id.id === preferredPrimaryId);
        if (idx > 0) {
          const [preferred] = sorted.splice(idx, 1);
          sorted.unshift(preferred);
        }
      }
      useIdentityStore.getState().setIdentities(sorted);
      syncIdentities();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to refresh identities';
      toast.error(message);
    }
  }, [client, syncIdentities]);

  // Focus trap with Escape handling
  const modalRef = useFocusTrap({
    isActive: isOpen,
    onEscape: onClose,
    restoreFocus: true,
  });

  // Close on click outside.
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (modalRef.current && !modalRef.current.contains(e.target as Node)) {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen, onClose, modalRef]);

  // Otevření dialogu vždy načte autoritativní profil ze Stalwartu. Webmail
  // namailu.cz identitu pouze upravuje; nové adresy a aliasy vznikají v portálu.
  useEffect(() => {
    if (isOpen) void refreshIdentities();
  }, [isOpen, refreshIdentities]);

  const handleUpdate = useCallback(async (identity: Identity, data: IdentityFormData) => {
    if (!client) return;

    try {
      await client.updateIdentity(identity.id, {
        name: data.name,
        replyTo: data.replyTo,
        bcc: data.bcc,
        textSignature: data.textSignature,
        htmlSignature: data.htmlSignature,
      });

      await refreshIdentities();
      toast.success(tNotif('identity_updated'));
      onClose();
    } catch (error) {
      const message = error instanceof Error ? error.message : t('validation_errors.unknown_error');
      toast.error(tNotif('identity_update_failed', { error: message }));
      throw error;
    }
  }, [client, refreshIdentities, t, tNotif, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-[1px] flex items-center justify-center z-50 p-4 animate-in fade-in duration-150">
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="identity-modal-title"
        className={cn(
          'bg-background border border-border rounded-lg shadow-xl',
          'w-full max-w-3xl max-h-[90vh] overflow-hidden',
          'animate-in zoom-in-95 duration-200'
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <div className="flex items-center gap-3">
            <Mail className="w-5 h-5 text-muted-foreground" />
            <h2 id="identity-modal-title" className="text-lg font-semibold text-foreground">
              {t('modal_title')}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md hover:bg-muted transition-colors duration-150 text-muted-foreground hover:text-foreground"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-80px)]">
          {identities[0] ? (
            <div>
              <h3 className="text-sm font-semibold mb-4">{t('edit_identity')}</h3>
              <IdentityForm
                key={identities[0].id}
                identity={identities[0]}
                onSave={(data) => handleUpdate(identities[0], data)}
                onCancel={onClose}
              />
            </div>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              <Mail className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p className="text-sm">{t('no_identities')}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
