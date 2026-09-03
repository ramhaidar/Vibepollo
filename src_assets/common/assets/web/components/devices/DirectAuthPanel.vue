<script setup lang="ts">
// Vibe Direct Auth v1 administration panel for the v2 Devices surface.
// These admin endpoints are only available to authenticated Web UI sessions.
// Enrollment setup URIs contain a one-time secret; this component only keeps
// them in memory and clears them when the server reports enrollment closed.
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';

import { ApiError, apiGet, apiPost } from '@/api/client';
import { AppButton, InlineAlert, StatusBadge, UiIcon } from '@/components/ui';

const { t } = useI18n();

interface DirectAuthEnrollment {
  open: boolean;
  enrollment_id?: string | null;
  expires_at_unix_ms?: number | null;
  setup_uri?: string | null;
}

interface DirectAuthPending {
  pending_id: string;
  fingerprint: string;
  name: string;
  uuid: string;
  source_ip?: string;
  created_at_unix_ms?: number;
  expires_at_unix_ms?: number;
}

interface DirectAuthBlocked {
  fingerprint: string;
  reason: string;
  name: string;
  uuid: string;
  created_at_unix_ms?: number;
}

interface DirectAuthSnapshot {
  status?: boolean;
  host_name?: string;
  host_uuid?: string;
  host_fingerprint?: string;
  enrollment: DirectAuthEnrollment;
  pending: DirectAuthPending[];
  blocked_revoked: DirectAuthBlocked[];
}

interface MutationResponse {
  status?: boolean;
  [key: string]: unknown;
}

interface PendingAction {
  kind: 'open' | 'close' | 'accept' | 'deny' | 'unblock';
  target: string;
}

const emit = defineEmits<{
  changed: [];
}>();

const loading = ref(true);
const error = ref('');
const notice = ref('');
const snapshot = ref<DirectAuthSnapshot>({
  enrollment: { open: false },
  pending: [],
  blocked_revoked: [],
});
const action = ref<PendingAction | null>(null);
const revealFingerprint = ref('');
const now = ref(Date.now());
const openedUri = ref('');
const reachableHost = ref('');
let refreshTimer: number | undefined;
let countdownTimer: number | undefined;

const enrollment = computed(() => snapshot.value.enrollment);
const enrollmentIsOpen = computed(() => Boolean(enrollment.value.open));
const pending = computed(() => snapshot.value.pending ?? []);
const blockedRevoked = computed(() => snapshot.value.blocked_revoked ?? []);
const blockedDevices = computed(() =>
  blockedRevoked.value.filter((entry) => entry.reason !== 'revoked'),
);
const revokedDevices = computed(() =>
  blockedRevoked.value.filter((entry) => entry.reason === 'revoked'),
);

const enrollmentSecondsLeft = computed(() => {
  if (!enrollmentIsOpen.value || !enrollment.value.expires_at_unix_ms) return 0;
  return Math.max(0, Math.ceil((enrollment.value.expires_at_unix_ms - now.value) / 1000));
});

const enrollmentExpiresLabel = computed(() => {
  const seconds = enrollmentSecondsLeft.value;
  if (seconds <= 0) return t('ui.devices.direct_auth.expired');
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return t('ui.devices.direct_auth.expires_in', {
    minutes: String(minutes).padStart(2, '0'),
    seconds: String(remainder).padStart(2, '0'),
  });
});

const activeAction = computed(() => Boolean(action.value));

function isLoopbackHost(value: string): boolean {
  const host = value.trim().toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || host.startsWith('127.');
}

function defaultReachableHost(): string {
  const host = window.location.hostname;
  return host && !isLoopbackHost(host) ? host : '';
}

function validReachableHost(value: string): boolean {
  const host = value.trim();
  return host.length > 0 && host.length <= 255 && !/[\r\n\0]/.test(host);
}

function busy(kind: PendingAction['kind'], target?: string): boolean {
  return Boolean(
    action.value &&
      action.value.kind === kind &&
      (target === undefined || action.value.target === target),
  );
}

function clearAction(): void {
  action.value = null;
}

function formatTimestamp(value: number | undefined, fallback: string): string {
  if (!value || !Number.isFinite(value)) return fallback;
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium',
      timeStyle: 'medium',
    }).format(new Date(value < 1_000_000_000_000 ? value * 1000 : value));
  } catch {
    return fallback;
  }
}

function userMessage(cause: unknown, key: string): string {
  if (cause instanceof ApiError) return t(key);
  if (cause instanceof Error) return cause.message;
  return t(key);
}

async function load(showLoading = false): Promise<void> {
  if (showLoading) loading.value = true;
  try {
    const response = await apiGet<DirectAuthSnapshot>('/api/direct-auth/status');
    if (response.status === false) throw new Error('rejected');
    snapshot.value = {
      enrollment: response.enrollment ?? { open: false },
      pending: response.pending ?? [],
      blocked_revoked: response.blocked_revoked ?? [],
      host_name: response.host_name,
      host_uuid: response.host_uuid,
      host_fingerprint: response.host_fingerprint,
    };
    error.value = '';
    if (!snapshot.value.enrollment.open) {
      // Never retain a stale setup URI after the server reports closed/consumed.
      openedUri.value = '';
      revealFingerprint.value = '';
    }
  } catch (cause) {
    error.value = userMessage(cause, 'ui.devices.direct_auth.error.load');
  } finally {
    loading.value = false;
  }
}

async function openEnrollment(): Promise<void> {
  error.value = '';
  notice.value = '';
  action.value = { kind: 'open', target: 'enrollment' };
  try {
    if (!validReachableHost(reachableHost.value)) {
      throw new Error(t('ui.devices.direct_auth.error.host_required'));
    }
    const response = await apiPost<{
      status?: boolean;
      enrollment?: DirectAuthEnrollment;
    }>('/api/direct-auth/enrollment', {
      host: reachableHost.value.trim(),
    });
    if (response.status !== true || !response.enrollment?.open) {
      throw new Error(t('ui.devices.direct_auth.error.open_rejected'));
    }
    openedUri.value = response.enrollment.setup_uri ?? '';
    notice.value = t('ui.devices.direct_auth.notice.opened');
    await load();
  } catch (cause) {
    error.value = userMessage(cause, 'ui.devices.direct_auth.error.open');
  } finally {
    clearAction();
  }
}

async function closeEnrollment(): Promise<void> {
  if (activeAction.value) return;
  error.value = '';
  notice.value = '';
  action.value = { kind: 'close', target: 'enrollment' };
  try {
    await apiPost<MutationResponse>('/api/direct-auth/enrollment/close', {});
    openedUri.value = '';
    await load();
    notice.value = t('ui.devices.direct_auth.notice.closed');
  } catch (cause) {
    error.value = userMessage(cause, 'ui.devices.direct_auth.error.close');
  } finally {
    clearAction();
  }
}

async function acceptPending(entry: DirectAuthPending): Promise<void> {
  if (activeAction.value) return;
  error.value = '';
  notice.value = '';
  action.value = { kind: 'accept', target: entry.pending_id };
  try {
    const response = await apiPost<MutationResponse>('/api/direct-auth/pending/accept', {
      pending_id: entry.pending_id,
    });
    if (response.status !== true)
      throw new Error(t('ui.devices.direct_auth.error.accept_rejected'));
    notice.value = t('ui.devices.direct_auth.notice.accepted', {
      name: entry.name || entry.fingerprint,
    });
    emit('changed');
    await load();
  } catch (cause) {
    error.value = userMessage(cause, 'ui.devices.direct_auth.error.accept');
  } finally {
    clearAction();
  }
}

async function denyPending(entry: DirectAuthPending): Promise<void> {
  if (activeAction.value) return;
  error.value = '';
  notice.value = '';
  action.value = { kind: 'deny', target: entry.pending_id };
  try {
    const response = await apiPost<MutationResponse>('/api/direct-auth/pending/deny', {
      pending_id: entry.pending_id,
    });
    if (response.status !== true) throw new Error(t('ui.devices.direct_auth.error.deny_rejected'));
    notice.value = t('ui.devices.direct_auth.notice.denied', {
      name: entry.name || entry.fingerprint,
    });
    await load();
  } catch (cause) {
    error.value = userMessage(cause, 'ui.devices.direct_auth.error.deny');
  } finally {
    clearAction();
  }
}

async function unblock(entry: DirectAuthBlocked): Promise<void> {
  if (activeAction.value) return;
  error.value = '';
  notice.value = '';
  action.value = { kind: 'unblock', target: entry.fingerprint };
  try {
    const response = await apiPost<MutationResponse>('/api/direct-auth/unblock', {
      fingerprint: entry.fingerprint,
    });
    if (response.status !== true)
      throw new Error(t('ui.devices.direct_auth.error.unblock_rejected'));
    notice.value = t('ui.devices.direct_auth.notice.unblocked', {
      name: entry.name || entry.fingerprint,
    });
    await load();
  } catch (cause) {
    error.value = userMessage(cause, 'ui.devices.direct_auth.error.unblock');
  } finally {
    clearAction();
  }
}

function copySetupUri(): void {
  const value = openedUri.value || enrollment.value.setup_uri;
  if (!value) return;
  try {
    void navigator.clipboard.writeText(value);
    notice.value = t('ui.devices.direct_auth.notice.copied');
  } catch {
    error.value = t('ui.devices.direct_auth.error.copy');
  }
}

function toggleReveal(fingerprint: string): void {
  revealFingerprint.value = revealFingerprint.value === fingerprint ? '' : fingerprint;
}

onMounted(() => {
  reachableHost.value = defaultReachableHost();
  void load(true);
  countdownTimer = window.setInterval(() => {
    now.value = Date.now();
  }, 1000);
  refreshTimer = window.setInterval(() => {
    void load();
  }, 5000);
});

onBeforeUnmount(() => {
  if (refreshTimer !== undefined) window.clearInterval(refreshTimer);
  if (countdownTimer !== undefined) window.clearInterval(countdownTimer);
});

defineExpose({
  refresh: () => load(),
});
</script>

<template>
  <section class="direct-auth vs-surface" :aria-label="t('ui.devices.direct_auth.section_aria')">
    <div class="direct-auth__heading">
      <div class="direct-auth__icon" aria-hidden="true"><UiIcon name="key" :size="20" /></div>
      <div>
        <h2>{{ t('ui.devices.direct_auth.title') }}</h2>
        <p>{{ t('ui.devices.direct_auth.description') }}</p>
      </div>
    </div>

    <InlineAlert
      v-if="error"
      tone="danger"
      :title="t('ui.devices.direct_auth.alert.failed')"
      announce="assertive"
      :dismiss-label="t('_common.dismiss')"
      @dismiss="error = ''"
    >
      {{ error }}
    </InlineAlert>
    <InlineAlert
      v-if="notice"
      tone="success"
      :title="t('ui.devices.direct_auth.alert.updated')"
      announce="polite"
      :dismiss-label="t('_common.dismiss')"
      @dismiss="notice = ''"
    >
      {{ notice }}
    </InlineAlert>

    <div v-if="loading" class="direct-auth__loading" role="status">
      {{ t('ui.devices.direct_auth.loading') }}
    </div>

    <template v-else>
      <div class="direct-auth__enrollment">
        <div v-if="enrollmentIsOpen" class="direct-auth__window">
          <div class="direct-auth__window-summary">
            <StatusBadge :label="t('ui.devices.direct_auth.status.open')" tone="success" compact />
            <span>{{ enrollmentExpiresLabel }}</span>
          </div>
          <p>{{ t('ui.devices.direct_auth.open_instructions') }}</p>
          <div v-if="openedUri || enrollment.setup_uri" class="direct-auth__uri">
            <code>{{ openedUri || enrollment.setup_uri }}</code>
            <AppButton
              :label="t('ui.devices.direct_auth.action.copy')"
              icon="copy"
              size="compact"
              :disabled="activeAction"
              @click="copySetupUri"
            />
          </div>
          <div class="direct-auth__window-actions">
            <AppButton
              :label="t('ui.devices.direct_auth.action.close')"
              variant="tertiary"
              size="compact"
              :busy="busy('close')"
              :disabled="activeAction && !busy('close')"
              @click="closeEnrollment"
            />
          </div>
        </div>
        <div v-else class="direct-auth__idle">
          <p>{{ t('ui.devices.direct_auth.idle_instructions') }}</p>
          <label class="direct-auth__host-field">
            <span>{{ t('ui.devices.direct_auth.reachable_host_label') }}</span>
            <input
              v-model="reachableHost"
              type="text"
              maxlength="255"
              autocomplete="off"
              :placeholder="t('ui.devices.direct_auth.reachable_host_placeholder')"
            />
          </label>
          <span v-if="!reachableHost" class="direct-auth__muted">
            {{ t('ui.devices.direct_auth.loopback_warning') }}
          </span>
          <div class="direct-auth__window-summary">
            <span>{{ t('ui.devices.direct_auth.default_expiry', { minutes: '02', seconds: '00' }) }}</span>
          </div>
          <AppButton
            :label="t('ui.devices.direct_auth.action.add_device')"
            icon="plus"
            variant="primary"
            :busy="busy('open')"
            :disabled="activeAction && !busy('open')"
            @click="openEnrollment"
          />
        </div>
      </div>

      <div v-if="pending.length" class="direct-auth__section">
        <h3>{{ t('ui.devices.direct_auth.pending.title') }}</h3>
        <ul class="direct-auth__list">
          <li v-for="entry in pending" :key="entry.pending_id" class="direct-auth__row">
            <div class="direct-auth__identity">
              <strong>{{ entry.name || t('ui.devices.direct_auth.unknown_name') }}</strong>
              <span>
                {{
                  formatTimestamp(
                    entry.created_at_unix_ms,
                    t('ui.devices.direct_auth.unknown_time'),
                  )
                }}
              </span>
              <span v-if="entry.source_ip" class="direct-auth__muted">{{ entry.source_ip }}</span>
              <button
                type="button"
                class="direct-auth__advanced"
                :aria-expanded="revealFingerprint === entry.fingerprint"
                @click="toggleReveal(entry.fingerprint)"
              >
                {{ t('ui.devices.direct_auth.action.fingerprint') }}
              </button>
              <code v-if="revealFingerprint === entry.fingerprint">{{ entry.fingerprint }}</code>
            </div>
            <div class="direct-auth__actions">
              <AppButton
                :label="t('ui.devices.direct_auth.action.allow')"
                icon="check"
                size="compact"
                :busy="busy('accept', entry.pending_id)"
                :disabled="activeAction && !busy('accept', entry.pending_id)"
                @click="acceptPending(entry)"
              />
              <AppButton
                :label="t('ui.devices.direct_auth.action.deny_block')"
                icon="x"
                variant="danger"
                size="compact"
                :busy="busy('deny', entry.pending_id)"
                :disabled="activeAction && !busy('deny', entry.pending_id)"
                @click="denyPending(entry)"
              />
            </div>
          </li>
        </ul>
      </div>

      <div v-if="blockedDevices.length || revokedDevices.length" class="direct-auth__section">
        <h3>{{ t('ui.devices.direct_auth.blocked.title') }}</h3>
        <ul class="direct-auth__list">
          <li
            v-for="entry in [...blockedDevices, ...revokedDevices]"
            :key="entry.fingerprint"
            class="direct-auth__row"
          >
            <div class="direct-auth__identity">
              <strong>{{ entry.name || entry.fingerprint }}</strong>
              <div class="direct-auth__badges">
                <StatusBadge
                  :label="
                    entry.reason === 'revoked'
                      ? t('ui.devices.direct_auth.status.revoked')
                      : t('ui.devices.direct_auth.status.blocked')
                  "
                  :tone="entry.reason === 'revoked' ? 'warning' : 'danger'"
                  compact
                />
                <button
                  type="button"
                  class="direct-auth__advanced"
                  :aria-expanded="revealFingerprint === entry.fingerprint"
                  @click="toggleReveal(entry.fingerprint)"
                >
                  {{ t('ui.devices.direct_auth.action.fingerprint') }}
                </button>
              </div>
              <code v-if="revealFingerprint === entry.fingerprint">{{ entry.fingerprint }}</code>
            </div>
            <div class="direct-auth__actions">
              <AppButton
                :label="t('ui.devices.direct_auth.action.unblock')"
                icon="refresh"
                variant="tertiary"
                size="compact"
                :busy="busy('unblock', entry.fingerprint)"
                :disabled="activeAction && !busy('unblock', entry.fingerprint)"
                @click="unblock(entry)"
              />
            </div>
          </li>
        </ul>
      </div>
    </template>
  </section>
</template>

<style scoped>
.direct-auth {
  display: grid;
  gap: var(--vs-space-16);
  padding: var(--vs-space-20);
}

.direct-auth__heading {
  display: flex;
  align-items: flex-start;
  gap: var(--vs-space-12);
}

.direct-auth__icon {
  display: grid;
  flex: 0 0 40px;
  width: 40px;
  height: 40px;
  place-items: center;
  border-radius: var(--vs-radius-control);
  background: var(--vs-color-bg-subtle);
  color: var(--vs-color-text-secondary);
}

.direct-auth__heading h2 {
  margin: 0;
  font-size: var(--vs-type-size-section);
  line-height: var(--vs-type-line-height-section);
}

.direct-auth__heading p,
.direct-auth__muted {
  color: var(--vs-color-text-secondary);
}

.direct-auth__heading p {
  margin: var(--vs-space-2) 0 0;
}

.direct-auth__loading {
  padding: var(--vs-space-16);
  color: var(--vs-color-text-secondary);
}

.direct-auth__enrollment {
  padding-top: var(--vs-space-4);
  border-top: 1px solid var(--vs-color-border-subtle);
}

.direct-auth__window,
.direct-auth__idle {
  display: grid;
  gap: var(--vs-space-12);
}

.direct-auth__host-field {
  display: grid;
  gap: var(--vs-space-6);
  max-width: 32rem;
}

.direct-auth__host-field input {
  width: 100%;
  padding: var(--vs-space-8) var(--vs-space-12);
  border: 1px solid var(--vs-color-border-default);
  border-radius: var(--vs-radius-control);
  background: var(--vs-color-bg-default);
  color: var(--vs-color-text-primary);
}

.direct-auth__window-summary,
.direct-auth__badges {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--vs-space-8);
}

.direct-auth__window-summary span {
  color: var(--vs-color-text-secondary);
  font-size: var(--vs-type-size-metadata);
}

.direct-auth__uri {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: var(--vs-space-8);
}

.direct-auth__uri code {
  overflow: hidden;
  padding: var(--vs-space-8) var(--vs-space-12);
  border: 1px solid var(--vs-color-border-subtle);
  border-radius: var(--vs-radius-control);
  background: var(--vs-color-bg-subtle);
  color: var(--vs-color-text-secondary);
  font-size: var(--vs-type-size-metadata);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.direct-auth__window-actions {
  display: flex;
  justify-content: flex-end;
}

.direct-auth__section {
  display: grid;
  gap: var(--vs-space-12);
  padding-top: var(--vs-space-16);
  border-top: 1px solid var(--vs-color-border-subtle);
}

.direct-auth__section h3 {
  margin: 0;
  font-size: var(--vs-type-size-control);
  color: var(--vs-color-text-primary);
}

.direct-auth__list {
  display: grid;
  gap: var(--vs-space-8);
  padding: 0;
  margin: 0;
  list-style: none;
}

.direct-auth__row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--vs-space-12);
  padding: var(--vs-space-12);
  border: 1px solid var(--vs-color-border-subtle);
  border-radius: var(--vs-radius-control);
  background: var(--vs-color-bg-subtle);
}

.direct-auth__identity {
  display: grid;
  min-width: 0;
  gap: var(--vs-space-4);
  color: var(--vs-color-text-primary);
}

.direct-auth__identity strong {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.direct-auth__identity code {
  overflow: hidden;
  color: var(--vs-color-text-muted);
  font-size: var(--vs-type-size-metadata);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.direct-auth__advanced {
  justify-self: start;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--vs-color-accent-default);
  font-size: var(--vs-type-size-metadata);
  cursor: pointer;
}

.direct-auth__actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--vs-space-8);
}

@media (max-width: 767px) {
  .direct-auth__uri {
    grid-template-columns: minmax(0, 1fr);
  }

  .direct-auth__row {
    align-items: stretch;
  }
}

@media (forced-colors: active) {
  .direct-auth__icon,
  .direct-auth__row {
    border: 1px solid CanvasText;
  }
}
</style>
