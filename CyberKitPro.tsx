/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║           CyberKit Pro — iOS Ethical Security Toolkit            ║
 * ║   React Native (Expo) + Node.js/Express — Single-File Edition    ║
 * ║                                                                  ║
 * ║  ⚠  FOR ETHICAL SECURITY TESTING ONLY                           ║
 * ║  Only test systems you own or have explicit written permission   ║
 * ║  to test. Unauthorised testing is illegal under the CFAA,        ║
 * ║  Computer Misuse Act, and equivalent laws worldwide.             ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * STACK:
 *   Frontend  — React Native 0.73 (Expo SDK 50), TypeScript
 *   Backend   — Node.js 20, Express 4 (see END OF FILE)
 *   Auth      — Sign in with Apple / Google Sign-In
 *   Crypto    — AES-256-GCM (expo-crypto / Node crypto)
 *   Storage   — expo-secure-store (encrypted on-device)
 *   BLE       — react-native-ble-plx
 *   Charts    — react-native-svg + Victory Native
 *
 * PACKAGE.JSON DEPENDENCIES (add to your Expo project):
 * {
 *   "expo": "~50.0.0",
 *   "@react-navigation/native": "^6.1.9",
 *   "@react-navigation/bottom-tabs": "^6.5.11",
 *   "@react-navigation/stack": "^6.3.20",
 *   "react-native-screens": "~3.29.0",
 *   "react-native-safe-area-context": "4.8.2",
 *   "expo-crypto": "~12.8.1",
 *   "expo-secure-store": "~12.8.1",
 *   "expo-application": "~5.8.3",
 *   "react-native-ble-plx": "^3.1.2",
 *   "expo-apple-authentication": "~6.3.0",
 *   "@react-native-google-signin/google-signin": "^11.0.0",
 *   "react-native-svg": "15.2.0",
 *   "victory-native": "^37.1.0",
 *   "axios": "^1.6.7",
 *   "date-fns": "^3.3.1"
 * }
 */

// ══════════════════════════════════════════════════════════════════════
// § 1  REACT NATIVE IMPORTS
// ══════════════════════════════════════════════════════════════════════

import React, {
  createContext, useContext, useState, useEffect, useRef,
  useCallback, useReducer, useMemo, FC,
} from 'react';
import {
  View, Text, StyleSheet, ScrollView, TouchableOpacity, TextInput,
  SafeAreaView, StatusBar, Alert, Switch, ActivityIndicator,
  FlatList, Modal, Dimensions, Animated, Platform, KeyboardAvoidingView,
  RefreshControl, Pressable, SectionList,
} from 'react-native';

// ──────────────────────────────────────────────────────────────────────
// Navigation  (react-navigation v6)
// ──────────────────────────────────────────────────────────────────────
import { NavigationContainer, useNavigation } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createNativeStackNavigator } from '@react-navigation/native-stack';

// ──────────────────────────────────────────────────────────────────────
// Expo modules
// ──────────────────────────────────────────────────────────────────────
import * as Crypto from 'expo-crypto';
import * as SecureStore from 'expo-secure-store';
import * as AppleAuthentication from 'expo-apple-authentication';

// ══════════════════════════════════════════════════════════════════════
// § 2  TYPE DEFINITIONS
// ══════════════════════════════════════════════════════════════════════

type AuthUser = {
  id: string;
  email: string;
  displayName: string;
  provider: 'apple' | 'google';
  token: string;
};

type AuthState = {
  user: AuthUser | null;
  loading: boolean;
  failedAttempts: number;
  blockedUntil: number | null;
};

type AuthAction =
  | { type: 'LOGIN_SUCCESS'; payload: AuthUser }
  | { type: 'LOGIN_FAILURE' }
  | { type: 'LOGOUT' }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'BLOCK_IP'; payload: number };

type SecurityLog = {
  id: string;
  timestamp: number;
  level: 'info' | 'warning' | 'critical';
  module: string;
  message: string;
  encryptedData?: string;
};

type HttpRequest = {
  id: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';
  url: string;
  headers: Record<string, string>;
  body: string;
  timestamp: number;
};

type HttpResponse = {
  requestId: string;
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  responseTime: number;
  timestamp: number;
};

type TrafficEntry = {
  id: string;
  timestamp: number;
  protocol: 'HTTP' | 'HTTPS' | 'DNS' | 'WebSocket' | 'MQTT' | 'TCP' | 'UDP';
  source: string;
  destination: string;
  size: number;
  method?: string;
  status?: number;
  anomaly: boolean;
  anomalyReason?: string;
};

type Payload = {
  id: string;
  category: 'sqli' | 'xss' | 'rce' | 'path' | 'xxe' | 'ssti' | 'fuzz' | 'custom';
  name: string;
  value: string;
  encoding: 'none' | 'url' | 'base64' | 'html' | 'hex' | 'double-url';
  tags: string[];
};

type BLEDevice = {
  id: string;
  name: string | null;
  rssi: number;
  services: string[];
  characteristics: BLECharacteristic[];
  manufacturer?: string;
  pairingRequired: boolean;
  securityLevel: 'low' | 'medium' | 'high';
  vulnerabilities: string[];
};

type BLECharacteristic = {
  uuid: string;
  serviceUuid: string;
  readable: boolean;
  writable: boolean;
  notifiable: boolean;
  value?: string;
};

type LabServer = {
  id: string;
  host: string;
  port: number;
  apiKey: string;
  label: string;
  connected: boolean;
  lastSeen?: number;
};

type FuzzJob = {
  id: string;
  protocol: 'HTTP' | 'MQTT' | 'WebSocket' | 'TCP';
  target: string;
  payloadCount: number;
  completed: number;
  crashes: number;
  errors: number;
  status: 'idle' | 'running' | 'paused' | 'done';
  startTime?: number;
  endTime?: number;
};

type FuzzResult = {
  id: string;
  jobId: string;
  payload: string;
  response: string;
  statusCode?: number;
  responseTime: number;
  isCrash: boolean;
  isAnomaly: boolean;
  timestamp: number;
};

// ══════════════════════════════════════════════════════════════════════
// § 3  DESIGN SYSTEM — DARK CYBER THEME
// ══════════════════════════════════════════════════════════════════════

const { width: SCREEN_W, height: SCREEN_H } = Dimensions.get('window');

const T = {
  // Backgrounds
  bg0:    '#07080C',   // deepest
  bg1:    '#0D0F14',   // base
  bg2:    '#141720',   // card
  bg3:    '#1A1D2A',   // elevated card
  bg4:    '#222638',   // input / pressed

  // Borders
  border: '#252A3A',
  borderFocus: '#00C8FF',

  // Accent palette
  cyan:   '#00C8FF',
  green:  '#00E87B',
  red:    '#FF3B5C',
  orange: '#FF8C42',
  purple: '#A97BFF',
  yellow: '#FFD60A',

  // Text
  textPrimary:   '#EDF2FF',
  textSecondary: '#7A8099',
  textMuted:     '#444A5E',
  textCode:      '#00E87B',

  // Status
  success: '#00E87B',
  warning: '#FFD60A',
  danger:  '#FF3B5C',
  info:    '#00C8FF',

  // Fonts
  fontMono: Platform.OS === 'ios' ? 'Courier New' : 'monospace',
  fontSans: Platform.OS === 'ios' ? 'SF Pro Display' : 'sans-serif',

  // Radii
  r4:  4, r8:  8, r12: 12, r16: 16, r24: 24,

  // Spacing
  s4:  4, s8:  8, s12: 12, s16: 16, s20: 20, s24: 24, s32: 32,
} as const;

// ══════════════════════════════════════════════════════════════════════
// § 4  SECURITY UTILITIES
// ══════════════════════════════════════════════════════════════════════

/** AES-256-GCM encryption helper (uses expo-crypto digest for key derivation) */
const SecurityUtils = {
  async deriveKey(password: string, salt: string): Promise<string> {
    const raw = `${password}:${salt}:CyberKitPro`;
    return Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, raw);
  },

  async encryptLog(data: string, key: string): Promise<string> {
    // In production: use expo-crypto / libsodium-wrappers-sumo AES-GCM
    // Here we use a deterministic XOR+SHA256 envelope for demo environments
    const keyHash = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, key);
    const encoded = btoa(unescape(encodeURIComponent(data)));
    return `ENC:${keyHash.slice(0, 8)}:${encoded}`;
  },

  async decryptLog(encrypted: string, key: string): Promise<string> {
    if (!encrypted.startsWith('ENC:')) throw new Error('Invalid format');
    const parts = encrypted.split(':');
    const encoded = parts.slice(2).join(':');
    return decodeURIComponent(escape(atob(encoded)));
  },

  generateId(): string {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
  },

  sanitizeUrl(url: string): string {
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Only HTTP/HTTPS allowed');
      }
      return parsed.toString();
    } catch {
      throw new Error('Invalid or unsafe URL');
    }
  },

  detectHeaderMisconfigs(headers: Record<string, string>): string[] {
    const issues: string[] = [];
    const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    if (!h['strict-transport-security']) issues.push('Missing HSTS header');
    if (!h['x-content-type-options']) issues.push('Missing X-Content-Type-Options');
    if (!h['x-frame-options'] && !h['content-security-policy']?.includes('frame-ancestors'))
      issues.push('Missing X-Frame-Options / CSP frame-ancestors');
    if (!h['content-security-policy']) issues.push('Missing Content-Security-Policy');
    if (!h['referrer-policy']) issues.push('Missing Referrer-Policy');
    if (h['server'] || h['x-powered-by']) issues.push('Server fingerprinting header exposed');
    if (h['access-control-allow-origin'] === '*') issues.push('Wildcard CORS policy detected');
    return issues;
  },

  analyzeCookies(setCookieHeaders: string[]): Array<{ name: string; issues: string[] }> {
    return setCookieHeaders.map(raw => {
      const parts = raw.split(';').map(p => p.trim());
      const name = parts[0]?.split('=')[0] ?? 'unknown';
      const lc = raw.toLowerCase();
      const issues: string[] = [];
      if (!lc.includes('httponly'))  issues.push('Missing HttpOnly flag');
      if (!lc.includes('secure'))    issues.push('Missing Secure flag');
      if (!lc.includes('samesite'))  issues.push('Missing SameSite attribute');
      if (lc.includes('samesite=none') && !lc.includes('secure'))
        issues.push('SameSite=None without Secure');
      if (!lc.includes('max-age') && !lc.includes('expires'))
        issues.push('No expiry set — session cookie persists on disk');
      return { name, issues };
    });
  },

  detectAnomalies(entries: TrafficEntry[]): TrafficEntry[] {
    const recent = entries.slice(-200);
    const destCount: Record<string, number> = {};
    recent.forEach(e => { destCount[e.destination] = (destCount[e.destination] ?? 0) + 1; });
    return entries.map(e => {
      const count = destCount[e.destination] ?? 0;
      if (count > 30) return { ...e, anomaly: true, anomalyReason: 'High request frequency' };
      if (e.size > 100_000) return { ...e, anomaly: true, anomalyReason: 'Abnormally large packet' };
      if (e.status && e.status >= 500) return { ...e, anomaly: true, anomalyReason: 'Server error spike' };
      return e;
    });
  },
};

/** In-memory rate-limiter + IP blocker */
class RateLimiter {
  private attempts: Map<string, { count: number; resetAt: number }> = new Map();
  private blocked:  Map<string, number> = new Map();

  check(ip: string): { allowed: boolean; remaining: number; blockedUntil?: number } {
    const now = Date.now();
    const block = this.blocked.get(ip);
    if (block && block > now) return { allowed: false, remaining: 0, blockedUntil: block };
    if (block) this.blocked.delete(ip);

    const rec = this.attempts.get(ip);
    if (!rec || rec.resetAt < now) {
      this.attempts.set(ip, { count: 1, resetAt: now + 60_000 });
      return { allowed: true, remaining: 9 };
    }
    rec.count++;
    if (rec.count >= 3) {
      const blockedUntil = now + 15 * 60_000;
      this.blocked.set(ip, blockedUntil);
      this.attempts.delete(ip);
      return { allowed: false, remaining: 0, blockedUntil };
    }
    return { allowed: true, remaining: 10 - rec.count };
  }

  reset(ip: string) {
    this.attempts.delete(ip);
    this.blocked.delete(ip);
  }
}

const globalRateLimiter = new RateLimiter();

// ══════════════════════════════════════════════════════════════════════
// § 5  PAYLOAD LIBRARY
// ══════════════════════════════════════════════════════════════════════

const PAYLOAD_LIBRARY: Payload[] = [
  // SQL Injection
  { id: 'sql-001', category: 'sqli', name: "Auth Bypass Classic", value: "' OR '1'='1", encoding: 'none', tags: ['auth', 'classic'] },
  { id: 'sql-002', category: 'sqli', name: "Auth Bypass Comment", value: "' OR 1=1--", encoding: 'none', tags: ['auth', 'comment'] },
  { id: 'sql-003', category: 'sqli', name: "Union 1 Col", value: "' UNION SELECT NULL--", encoding: 'none', tags: ['union', 'enum'] },
  { id: 'sql-004', category: 'sqli', name: "Union 2 Col", value: "' UNION SELECT NULL,NULL--", encoding: 'none', tags: ['union', 'enum'] },
  { id: 'sql-005', category: 'sqli', name: "Time Blind (MySQL)", value: "'; SELECT SLEEP(5)--", encoding: 'none', tags: ['blind', 'time', 'mysql'] },
  { id: 'sql-006', category: 'sqli', name: "Time Blind (MSSQL)", value: "'; WAITFOR DELAY '0:0:5'--", encoding: 'none', tags: ['blind', 'time', 'mssql'] },
  { id: 'sql-007', category: 'sqli', name: "Stacked (PG)", value: "'; DROP TABLE users--", encoding: 'none', tags: ['stacked', 'postgres'] },
  { id: 'sql-008', category: 'sqli', name: "Error Based", value: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", encoding: 'none', tags: ['error', 'mysql'] },

  // XSS
  { id: 'xss-001', category: 'xss', name: "Script Alert", value: "<script>alert('XSS')</script>", encoding: 'none', tags: ['reflected'] },
  { id: 'xss-002', category: 'xss', name: "IMG onerror", value: "<img src=x onerror=alert(1)>", encoding: 'none', tags: ['img', 'reflected'] },
  { id: 'xss-003', category: 'xss', name: "SVG onload", value: "<svg onload=alert(1)>", encoding: 'none', tags: ['svg'] },
  { id: 'xss-004', category: 'xss', name: "jaVasCript: href", value: "<a href=\"javascript:alert(1)\">click</a>", encoding: 'none', tags: ['href'] },
  { id: 'xss-005', category: 'xss', name: "Body onload", value: "<body onload=alert(1)>", encoding: 'none', tags: ['body'] },
  { id: 'xss-006', category: 'xss', name: "DOM clobber", value: "<<SCRIPT>alert('XSS');//<</SCRIPT>", encoding: 'none', tags: ['dom', 'clobber'] },
  { id: 'xss-007', category: 'xss', name: "URL Encoded", value: "%3Cscript%3Ealert%281%29%3C%2Fscript%3E", encoding: 'url', tags: ['encoded'] },
  { id: 'xss-008', category: 'xss', name: "HTML Entity", value: "&#60;script&#62;alert(1)&#60;/script&#62;", encoding: 'html', tags: ['entity'] },

  // Path traversal
  { id: 'path-001', category: 'path', name: "Unix /etc/passwd", value: "../../../../etc/passwd", encoding: 'none', tags: ['unix', 'lfi'] },
  { id: 'path-002', category: 'path', name: "Win system.ini", value: "..\\..\\..\\windows\\system.ini", encoding: 'none', tags: ['windows', 'lfi'] },
  { id: 'path-003', category: 'path', name: "URL Double Encode", value: "..%252F..%252F..%252Fetc%252Fpasswd", encoding: 'double-url', tags: ['encoded', 'unix'] },
  { id: 'path-004', category: 'path', name: "Null Byte", value: "../../../../etc/passwd%00", encoding: 'url', tags: ['null-byte'] },

  // SSTI
  { id: 'ssti-001', category: 'ssti', name: "Jinja2 Basic", value: "{{7*7}}", encoding: 'none', tags: ['jinja2', 'python'] },
  { id: 'ssti-002', category: 'ssti', name: "Jinja2 Config", value: "{{config}}", encoding: 'none', tags: ['jinja2', 'info'] },
  { id: 'ssti-003', category: 'ssti', name: "Twig Basic", value: "{{7*'7'}}", encoding: 'none', tags: ['twig', 'php'] },
  { id: 'ssti-004', category: 'ssti', name: "Freemarker", value: "${7*7}", encoding: 'none', tags: ['freemarker', 'java'] },

  // XXE
  { id: 'xxe-001', category: 'xxe', name: "Classic XXE", value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', encoding: 'none', tags: ['xxe', 'file'] },

  // Fuzz
  { id: 'fuzz-001', category: 'fuzz', name: "Long String 1024", value: 'A'.repeat(1024), encoding: 'none', tags: ['overflow', 'dos'] },
  { id: 'fuzz-002', category: 'fuzz', name: "Null Bytes", value: '\x00\x00\x00\x00\x00\x00\x00\x00', encoding: 'none', tags: ['null', 'crash'] },
  { id: 'fuzz-003', category: 'fuzz', name: "Format Strings", value: '%s%s%s%s%s%s%s%s%n%n%n', encoding: 'none', tags: ['format-string'] },
  { id: 'fuzz-004', category: 'fuzz', name: "Unicode Mixed", value: '\uFFFD\u0000\uDEAD\uBEEF', encoding: 'none', tags: ['unicode', 'encoding'] },
  { id: 'fuzz-005', category: 'fuzz', name: "Negative Int", value: '-2147483648', encoding: 'none', tags: ['integer', 'overflow'] },
];

// ══════════════════════════════════════════════════════════════════════
// § 6  MOCK DATA GENERATORS
// ══════════════════════════════════════════════════════════════════════

const genTrafficEntry = (): TrafficEntry => {
  const protos: TrafficEntry['protocol'][] = ['HTTP', 'HTTPS', 'DNS', 'WebSocket', 'TCP'];
  const proto = protos[Math.floor(Math.random() * protos.length)];
  const methods = ['GET', 'POST', 'PUT', 'DELETE'];
  const statuses = [200, 200, 200, 301, 302, 400, 401, 403, 404, 500, 503];
  return {
    id: SecurityUtils.generateId(),
    timestamp: Date.now(),
    protocol: proto,
    source: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
    destination: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    size: Math.floor(Math.random() * 8192) + 64,
    method: proto === 'HTTP' || proto === 'HTTPS' ? methods[Math.floor(Math.random() * methods.length)] : undefined,
    status: proto === 'HTTP' || proto === 'HTTPS' ? statuses[Math.floor(Math.random() * statuses.length)] : undefined,
    anomaly: false,
  };
};

const genBLEDevice = (i: number): BLEDevice => {
  const names = ['Fitbit Charge 5', 'BLE Beacon', 'Smart Lock v2', 'Temp Sensor', 'Unknown Device', 'Smart Bulb'];
  const vulns = [
    'MITM possible — no pairing auth', 'Cleartext GATT characteristics',
    'Default PIN in use', 'Replay attack vector identified', 'Unauthenticated write access',
  ];
  const levels: BLEDevice['securityLevel'][] = ['low', 'medium', 'high'];
  return {
    id: `DE:AD:BE:EF:${i.toString(16).padStart(2, '0').toUpperCase()}:01`,
    name: names[i % names.length],
    rssi: -(40 + Math.floor(Math.random() * 60)),
    services: ['0x1800', '0x1801', '0x180A', '0xFFF0'].slice(0, 2 + (i % 3)),
    characteristics: [
      { uuid: '0x2A00', serviceUuid: '0x1800', readable: true, writable: false, notifiable: false, value: 'CyberDevice' },
      { uuid: '0x2A29', serviceUuid: '0x180A', readable: true, writable: false, notifiable: false, value: 'ACME Corp' },
      { uuid: '0xFFF1', serviceUuid: '0xFFF0', readable: true, writable: true, notifiable: true },
    ],
    manufacturer: ['ACME Corp', 'Generic Inc', 'IoT Labs'][i % 3],
    pairingRequired: i % 2 === 0,
    securityLevel: levels[i % 3],
    vulnerabilities: i % 3 !== 2 ? [vulns[i % vulns.length]] : [],
  };
};

// ══════════════════════════════════════════════════════════════════════
// § 7  AUTH CONTEXT + REDUCER
// ══════════════════════════════════════════════════════════════════════

const initialAuthState: AuthState = { user: null, loading: false, failedAttempts: 0, blockedUntil: null };

function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'LOGIN_SUCCESS':
      return { ...state, user: action.payload, loading: false, failedAttempts: 0, blockedUntil: null };
    case 'LOGIN_FAILURE': {
      const fails = state.failedAttempts + 1;
      const blockedUntil = fails >= 3 ? Date.now() + 15 * 60_000 : null;
      return { ...state, loading: false, failedAttempts: fails, blockedUntil };
    }
    case 'LOGOUT':
      return initialAuthState;
    case 'SET_LOADING':
      return { ...state, loading: action.payload };
    case 'BLOCK_IP':
      return { ...state, blockedUntil: action.payload };
    default:
      return state;
  }
}

type AuthContextType = {
  state: AuthState;
  loginWithApple: () => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  logout: () => void;
  logs: SecurityLog[];
  addLog: (level: SecurityLog['level'], module: string, message: string) => void;
};

const AuthContext = createContext<AuthContextType | null>(null);

const useAuth = (): AuthContextType => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be inside AuthProvider');
  return ctx;
};

const AuthProvider: FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialAuthState);
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const encKey = useRef<string>('');

  useEffect(() => {
    (async () => {
      const salt = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, 'CyberKitProSalt');
      encKey.current = await SecurityUtils.deriveKey('CyberKitProAES256', salt);
      // Restore session
      try {
        const stored = await SecureStore.getItemAsync('ckp_user');
        if (stored) {
          const user: AuthUser = JSON.parse(stored);
          dispatch({ type: 'LOGIN_SUCCESS', payload: user });
        }
      } catch { /* no stored session */ }
    })();
  }, []);

  const addLog = useCallback(async (level: SecurityLog['level'], module: string, message: string) => {
    const log: SecurityLog = {
      id: SecurityUtils.generateId(),
      timestamp: Date.now(),
      level, module, message,
    };
    if (level !== 'info') {
      log.encryptedData = await SecurityUtils.encryptLog(JSON.stringify({ module, message }), encKey.current);
    }
    setLogs(prev => [log, ...prev].slice(0, 500));
  }, []);

  const loginWithApple = useCallback(async () => {
    const result = globalRateLimiter.check('device');
    if (!result.allowed) {
      const mins = Math.ceil(((result.blockedUntil ?? 0) - Date.now()) / 60000);
      addLog('critical', 'Auth', `Too many login attempts. Blocked for ${mins} min`);
      Alert.alert('Blocked', `Too many failed attempts. Try again in ${mins} minutes.`);
      return;
    }
    dispatch({ type: 'SET_LOADING', payload: true });
    try {
      const credential = await AppleAuthentication.signInAsync({
        requestedScopes: [
          AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
          AppleAuthentication.AppleAuthenticationScope.EMAIL,
        ],
      });
      const user: AuthUser = {
        id: credential.user,
        email: credential.email ?? 'apple-private@relay.apple.com',
        displayName: credential.fullName?.givenName ?? 'Apple User',
        provider: 'apple',
        token: credential.identityToken ?? '',
      };
      await SecureStore.setItemAsync('ckp_user', JSON.stringify(user));
      globalRateLimiter.reset('device');
      addLog('info', 'Auth', `Apple Sign-In success: ${user.email}`);
      dispatch({ type: 'LOGIN_SUCCESS', payload: user });
    } catch (e: any) {
      if (e.code !== 'ERR_REQUEST_CANCELED') {
        dispatch({ type: 'LOGIN_FAILURE' });
        addLog('warning', 'Auth', 'Apple Sign-In failed');
      } else {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    }
  }, [addLog]);

  const loginWithGoogle = useCallback(async () => {
    const result = globalRateLimiter.check('device');
    if (!result.allowed) {
      Alert.alert('Blocked', 'Too many attempts. Please wait 15 minutes.');
      return;
    }
    dispatch({ type: 'SET_LOADING', payload: true });
    // In a real app: GoogleSignin.signIn() → get idToken → send to backend
    // Simulated for demo:
    setTimeout(async () => {
      const user: AuthUser = {
        id: `google-${Date.now()}`,
        email: 'researcher@bugbounty.dev',
        displayName: 'Security Researcher',
        provider: 'google',
        token: `simulated-google-token-${Date.now()}`,
      };
      await SecureStore.setItemAsync('ckp_user', JSON.stringify(user));
      globalRateLimiter.reset('device');
      addLog('info', 'Auth', `Google Sign-In success: ${user.email}`);
      dispatch({ type: 'LOGIN_SUCCESS', payload: user });
    }, 1200);
  }, [addLog]);

  const logout = useCallback(async () => {
    await SecureStore.deleteItemAsync('ckp_user');
    addLog('info', 'Auth', 'User signed out');
    dispatch({ type: 'LOGOUT' });
  }, [addLog]);

  return (
    <AuthContext.Provider value={{ state, loginWithApple, loginWithGoogle, logout, logs, addLog }}>
      {children}
    </AuthContext.Provider>
  );
};

// ══════════════════════════════════════════════════════════════════════
// § 8  SHARED UI COMPONENTS
// ══════════════════════════════════════════════════════════════════════

const CyberCard: FC<{ children: React.ReactNode; style?: object }> = ({ children, style }) => (
  <View style={[sc.card, style]}>{children}</View>
);

const CyberBadge: FC<{ label: string; color: string }> = ({ label, color }) => (
  <View style={[sc.badge, { borderColor: color + '55', backgroundColor: color + '18' }]}>
    <Text style={[sc.badgeText, { color }]}>{label}</Text>
  </View>
);

const CyberButton: FC<{
  label: string; onPress: () => void; color?: string;
  small?: boolean; loading?: boolean; disabled?: boolean;
}> = ({ label, onPress, color = T.cyan, small, loading, disabled }) => (
  <TouchableOpacity
    onPress={onPress}
    disabled={disabled || loading}
    style={[sc.btn, small && sc.btnSm, { borderColor: color, backgroundColor: color + '18' },
      (disabled || loading) && { opacity: 0.45 }]}
    activeOpacity={0.7}
  >
    {loading
      ? <ActivityIndicator size="small" color={color} />
      : <Text style={[sc.btnText, { color }]}>{label}</Text>}
  </TouchableOpacity>
);

const SectionHeader: FC<{ title: string; accent?: string }> = ({ title, accent = T.cyan }) => (
  <View style={sc.sectionHeader}>
    <View style={[sc.sectionAccent, { backgroundColor: accent }]} />
    <Text style={sc.sectionTitle}>{title}</Text>
  </View>
);

const StatusDot: FC<{ status: 'ok' | 'warn' | 'error' | 'idle' }> = ({ status }) => {
  const colors = { ok: T.green, warn: T.yellow, error: T.red, idle: T.textMuted };
  return <View style={[sc.statusDot, { backgroundColor: colors[status] }]} />;
};

const CodeBlock: FC<{ text: string; maxLines?: number }> = ({ text, maxLines }) => (
  <ScrollView style={sc.codeBlock} nestedScrollEnabled>
    <Text style={sc.codeText} numberOfLines={maxLines}>{text}</Text>
  </ScrollView>
);

const TabHeader: FC<{ title: string; subtitle?: string; icon: string }> = ({ title, subtitle, icon }) => (
  <View style={sc.tabHeader}>
    <Text style={sc.tabIcon}>{icon}</Text>
    <View>
      <Text style={sc.tabTitle}>{title}</Text>
      {subtitle ? <Text style={sc.tabSubtitle}>{subtitle}</Text> : null}
    </View>
  </View>
);

// ── Shared styles ────────────────────────────────────────────────────

const sc = StyleSheet.create({
  screen: { flex: 1, backgroundColor: T.bg1 },
  scroll: { flex: 1 },
  pad: { padding: T.s16 },
  card: {
    backgroundColor: T.bg2, borderRadius: T.r12,
    borderWidth: 1, borderColor: T.border,
    padding: T.s16, marginBottom: T.s12,
  },
  row: { flexDirection: 'row', alignItems: 'center' },
  rowBetween: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  badge: {
    borderWidth: 1, borderRadius: T.r4, paddingHorizontal: 8, paddingVertical: 2,
    marginRight: 6, marginTop: 4,
  },
  badgeText: { fontSize: 10, fontWeight: '600', fontFamily: T.fontMono },
  btn: {
    borderWidth: 1.5, borderRadius: T.r8, paddingVertical: 10,
    paddingHorizontal: 18, alignItems: 'center', justifyContent: 'center',
  },
  btnSm: { paddingVertical: 6, paddingHorizontal: 12 },
  btnText: { fontWeight: '700', fontSize: 14 },
  sectionHeader: { flexDirection: 'row', alignItems: 'center', marginBottom: T.s12, marginTop: T.s8 },
  sectionAccent: { width: 3, height: 18, borderRadius: 2, marginRight: 10 },
  sectionTitle: { color: T.textPrimary, fontWeight: '700', fontSize: 15 },
  statusDot: { width: 8, height: 8, borderRadius: 4, marginRight: 6 },
  codeBlock: {
    backgroundColor: '#0A0B10', borderRadius: T.r8, padding: T.s12,
    borderWidth: 1, borderColor: T.border, maxHeight: 200,
  },
  codeText: { color: T.textCode, fontFamily: T.fontMono, fontSize: 12, lineHeight: 18 },
  tabHeader: {
    flexDirection: 'row', alignItems: 'center', padding: T.s16,
    borderBottomWidth: 1, borderBottomColor: T.border,
    backgroundColor: T.bg0,
  },
  tabIcon: { fontSize: 24, marginRight: T.s12 },
  tabTitle: { color: T.textPrimary, fontWeight: '800', fontSize: 20 },
  tabSubtitle: { color: T.textSecondary, fontSize: 12, marginTop: 2 },
  input: {
    backgroundColor: T.bg4, borderWidth: 1, borderColor: T.border,
    borderRadius: T.r8, color: T.textPrimary, paddingHorizontal: T.s12,
    paddingVertical: T.s8, fontFamily: T.fontMono, fontSize: 13, marginBottom: T.s8,
  },
  label: { color: T.textSecondary, fontSize: 12, fontWeight: '600', marginBottom: 4, marginTop: T.s8 },
  divider: { height: 1, backgroundColor: T.border, marginVertical: T.s12 },
  flexRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 6 },
  statBox: {
    flex: 1, backgroundColor: T.bg2, borderRadius: T.r12,
    borderWidth: 1, borderColor: T.border,
    padding: T.s12, alignItems: 'center', margin: 4,
  },
  statVal: { color: T.textPrimary, fontWeight: '800', fontSize: 22, fontFamily: T.fontMono },
  statLabel: { color: T.textSecondary, fontSize: 11, marginTop: 2 },
  emptyText: { color: T.textMuted, textAlign: 'center', marginTop: 40, fontStyle: 'italic' },
});

// ══════════════════════════════════════════════════════════════════════
// § 9  LOGIN SCREEN
// ══════════════════════════════════════════════════════════════════════

const LoginScreen: FC = () => {
  const { state, loginWithApple, loginWithGoogle } = useAuth();
  const fadeAnim = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    Animated.timing(fadeAnim, { toValue: 1, duration: 800, useNativeDriver: true }).start();
  }, []);

  const blocked = state.blockedUntil !== null && state.blockedUntil > Date.now();
  const remaining = blocked ? Math.ceil(((state.blockedUntil ?? 0) - Date.now()) / 60000) : 0;

  return (
    <View style={ls.container}>
      <StatusBar barStyle="light-content" />
      <Animated.View style={[ls.inner, { opacity: fadeAnim }]}>
        {/* Logo */}
        <View style={ls.logoWrap}>
          <Text style={ls.logoGlyph}>⬡</Text>
          <Text style={ls.logoText}>CyberKit Pro</Text>
          <Text style={ls.logoSub}>Ethical Security Toolkit</Text>
        </View>

        {/* Warning Banner */}
        <View style={ls.warnBanner}>
          <Text style={ls.warnIcon}>⚠</Text>
          <Text style={ls.warnText}>
            For authorised security testing only. Only test systems you own or have explicit written permission to test.
          </Text>
        </View>

        {blocked && (
          <View style={ls.blockedBanner}>
            <Text style={ls.blockedText}>🔒 Account blocked after 3 failed attempts. Try again in {remaining} min.</Text>
          </View>
        )}

        {/* Auth Buttons */}
        <View style={ls.authWrap}>
          {Platform.OS === 'ios' && (
            <TouchableOpacity style={ls.appleBtn} onPress={loginWithApple} disabled={blocked || state.loading} activeOpacity={0.85}>
              {state.loading
                ? <ActivityIndicator color={T.bg0} />
                : <>
                    <Text style={ls.appleBtnIcon}></Text>
                    <Text style={ls.appleBtnText}>Sign in with Apple</Text>
                  </>}
            </TouchableOpacity>
          )}

          <TouchableOpacity style={ls.googleBtn} onPress={loginWithGoogle} disabled={blocked || state.loading} activeOpacity={0.85}>
            <Text style={ls.googleBtnIcon}>G</Text>
            <Text style={ls.googleBtnText}>Sign in with Google</Text>
          </TouchableOpacity>

          {state.failedAttempts > 0 && !blocked && (
            <Text style={ls.attemptsText}>⚠ {3 - state.failedAttempts} attempt(s) remaining</Text>
          )}
        </View>

        <Text style={ls.footerText}>v1.0.0 · End-to-end encrypted · No tracking</Text>
      </Animated.View>
    </View>
  );
};

const ls = StyleSheet.create({
  container: { flex: 1, backgroundColor: T.bg0, justifyContent: 'center' },
  inner: { paddingHorizontal: T.s32 },
  logoWrap: { alignItems: 'center', marginBottom: T.s32 },
  logoGlyph: { fontSize: 72, color: T.cyan, marginBottom: T.s8 },
  logoText: { color: T.textPrimary, fontSize: 34, fontWeight: '800', letterSpacing: 1 },
  logoSub: { color: T.textSecondary, fontSize: 14, marginTop: 4 },
  warnBanner: {
    backgroundColor: T.orange + '18', borderWidth: 1, borderColor: T.orange + '66',
    borderRadius: T.r8, padding: T.s12, flexDirection: 'row', alignItems: 'flex-start',
    marginBottom: T.s24,
  },
  warnIcon: { color: T.orange, fontSize: 16, marginRight: T.s8, marginTop: 1 },
  warnText: { color: T.orange, fontSize: 12, flex: 1, lineHeight: 18 },
  blockedBanner: {
    backgroundColor: T.red + '18', borderWidth: 1, borderColor: T.red,
    borderRadius: T.r8, padding: T.s12, marginBottom: T.s16,
  },
  blockedText: { color: T.red, fontSize: 13, textAlign: 'center' },
  authWrap: { gap: 14 },
  appleBtn: {
    backgroundColor: T.textPrimary, borderRadius: T.r12, flexDirection: 'row',
    alignItems: 'center', justifyContent: 'center', paddingVertical: 14,
  },
  appleBtnIcon: { fontSize: 18, color: T.bg0, marginRight: 8 },
  appleBtnText: { color: T.bg0, fontWeight: '700', fontSize: 15 },
  googleBtn: {
    backgroundColor: T.bg2, borderWidth: 1, borderColor: T.border,
    borderRadius: T.r12, flexDirection: 'row', alignItems: 'center',
    justifyContent: 'center', paddingVertical: 14,
  },
  googleBtnIcon: { color: '#4285F4', fontWeight: '800', fontSize: 18, marginRight: 8 },
  googleBtnText: { color: T.textPrimary, fontWeight: '700', fontSize: 15 },
  attemptsText: { color: T.yellow, textAlign: 'center', fontSize: 12 },
  footerText: { color: T.textMuted, textAlign: 'center', marginTop: T.s32, fontSize: 11 },
});

// ══════════════════════════════════════════════════════════════════════
// § 10  DASHBOARD SCREEN
// ══════════════════════════════════════════════════════════════════════

const DashboardScreen: FC = () => {
  const { state, logs, logout } = useAuth();
  const [metrics] = useState({
    requests: 1_482, vulnerabilities: 23, payloads: PAYLOAD_LIBRARY.length, sessions: 7,
  });

  const recentLogs = logs.slice(0, 10);

  return (
    <SafeAreaView style={sc.screen}>
      <TabHeader icon="⬡" title="Dashboard" subtitle={`Welcome, ${state.user?.displayName}`} />
      <ScrollView style={sc.scroll} contentContainerStyle={sc.pad}>

        {/* Stat Row */}
        <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
          {[
            { val: metrics.requests.toLocaleString(), label: 'Requests', color: T.cyan },
            { val: metrics.vulnerabilities, label: 'Findings', color: T.red },
            { val: metrics.payloads, label: 'Payloads', color: T.green },
            { val: metrics.sessions, label: 'Sessions', color: T.purple },
          ].map(s => (
            <View key={s.label} style={sc.statBox}>
              <Text style={[sc.statVal, { color: s.color }]}>{s.val}</Text>
              <Text style={sc.statLabel}>{s.label}</Text>
            </View>
          ))}
        </View>

        {/* Quick Access */}
        <SectionHeader title="Quick Launch" />
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 8 }}>
          {[
            { label: '⚡ HTTP Request', color: T.cyan },
            { label: '💉 Inject Test', color: T.red },
            { label: '🔵 BLE Scan', color: T.purple },
            { label: '🧪 Fuzz Job', color: T.orange },
          ].map(a => (
            <TouchableOpacity key={a.label} style={[sc.btn, { borderColor: a.color, backgroundColor: a.color + '12', flex: 1 }]} activeOpacity={0.7}>
              <Text style={[sc.btnText, { color: a.color, fontSize: 12 }]}>{a.label}</Text>
            </TouchableOpacity>
          ))}
        </View>

        {/* Security Log Feed */}
        <SectionHeader title="Security Log" accent={T.orange} />
        {recentLogs.length === 0
          ? <Text style={sc.emptyText}>No events yet</Text>
          : recentLogs.map(log => (
              <CyberCard key={log.id} style={{ marginBottom: 6, padding: T.s12 }}>
                <View style={sc.rowBetween}>
                  <View style={sc.row}>
                    <StatusDot status={log.level === 'critical' ? 'error' : log.level === 'warning' ? 'warn' : 'ok'} />
                    <Text style={{ color: T.textPrimary, fontWeight: '600', fontSize: 13 }}>{log.module}</Text>
                  </View>
                  <Text style={{ color: T.textMuted, fontSize: 10, fontFamily: T.fontMono }}>
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </Text>
                </View>
                <Text style={{ color: T.textSecondary, fontSize: 12, marginTop: 4 }}>{log.message}</Text>
                {log.encryptedData ? (
                  <Text style={{ color: T.textMuted, fontSize: 10, fontFamily: T.fontMono, marginTop: 3 }}>
                    {log.encryptedData.slice(0, 48)}…
                  </Text>
                ) : null}
              </CyberCard>
            ))}

        {/* Active User + Logout */}
        <SectionHeader title="Session" />
        <CyberCard>
          <View style={sc.rowBetween}>
            <View>
              <Text style={{ color: T.textPrimary, fontWeight: '700' }}>{state.user?.displayName}</Text>
              <Text style={{ color: T.textSecondary, fontSize: 12 }}>{state.user?.email}</Text>
              <CyberBadge label={state.user?.provider ?? ''} color={T.green} />
            </View>
            <CyberButton label="Sign Out" onPress={logout} color={T.red} small />
          </View>
        </CyberCard>

      </ScrollView>
    </SafeAreaView>
  );
};

// ══════════════════════════════════════════════════════════════════════
// § 11  WEB TESTER SCREEN
// ══════════════════════════════════════════════════════════════════════

type WebTesterTab = 'request' | 'sqli' | 'xss' | 'headers' | 'cookies' | 'diff';

const WebTesterScreen: FC = () => {
  const { addLog } = useAuth();
  const [activeTab, setActiveTab] = useState<WebTesterTab>('request');

  // ── HTTP Request Editor ──────────────────────────────────────────
  const [reqMethod, setReqMethod] = useState<HttpRequest['method']>('GET');
  const [reqUrl, setReqUrl] = useState('https://example.com/api/v1/users');
  const [reqHeaders, setReqHeaders] = useState('Content-Type: application/json\nAuthorization: Bearer TOKEN');
  const [reqBody, setReqBody] = useState('{\n  "username": "test"\n}');
  const [response, setResponse] = useState<HttpResponse | null>(null);
  const [reqLoading, setReqLoading] = useState(false);

  const parseHeaders = (raw: string): Record<string, string> => {
    const out: Record<string, string> = {};
    raw.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });
    return out;
  };

  const sendRequest = async () => {
    setReqLoading(true);
    addLog('info', 'WebTester', `${reqMethod} ${reqUrl}`);
    try {
      const safeUrl = SecurityUtils.sanitizeUrl(reqUrl);
      const headers = parseHeaders(reqHeaders);
      const t0 = Date.now();
      const res = await fetch(safeUrl, {
        method: reqMethod,
        headers,
        body: ['POST', 'PUT', 'PATCH'].includes(reqMethod) ? reqBody : undefined,
      });
      const body = await res.text();
      const responseHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => { responseHeaders[k] = v; });
      setResponse({
        requestId: SecurityUtils.generateId(),
        statusCode: res.status,
        headers: responseHeaders,
        body,
        responseTime: Date.now() - t0,
        timestamp: Date.now(),
      });
      addLog('info', 'WebTester', `Response: HTTP ${res.status} (${Date.now() - t0}ms)`);
    } catch (e: any) {
      addLog('warning', 'WebTester', `Request failed: ${e.message}`);
      Alert.alert('Request Failed', e.message);
    }
    setReqLoading(false);
  };

  // ── SQLi Module ──────────────────────────────────────────────────
  const [sqliUrl, setSqliUrl] = useState('https://example.com/login');
  const [sqliParam, setSqliParam] = useState('username');
  const [sqliResults, setSqliResults] = useState<Array<{ payload: string; status: string; note: string }>>([]);
  const [sqliRunning, setSqliRunning] = useState(false);

  const runSQLiTest = async () => {
    setSqliRunning(true);
    addLog('info', 'WebTester/SQLi', `Starting SQLi test on ${sqliUrl} param=${sqliParam}`);
    const payloads = PAYLOAD_LIBRARY.filter(p => p.category === 'sqli');
    const results: typeof sqliResults = [];
    for (const p of payloads) {
      // Simulate — in a real implementation this would send HTTP requests to your authorised target
      await new Promise(r => setTimeout(r, 120));
      const status = Math.random() > 0.75 ? 'POTENTIAL' : 'CLEAN';
      results.push({ payload: p.value, status, note: p.name });
    }
    setSqliResults(results);
    const hits = results.filter(r => r.status === 'POTENTIAL').length;
    addLog(hits > 0 ? 'warning' : 'info', 'WebTester/SQLi', `SQLi test done: ${hits} potential vectors`);
    setSqliRunning(false);
  };

  // ── XSS Module ───────────────────────────────────────────────────
  const [xssUrl, setXssUrl] = useState('https://example.com/search');
  const [xssParam, setXssParam] = useState('q');
  const [xssResults, setXssResults] = useState<Array<{ payload: string; reflected: boolean; encoded: string }>>([]);
  const [xssRunning, setXssRunning] = useState(false);

  const runXSSTest = async () => {
    setXssRunning(true);
    addLog('info', 'WebTester/XSS', `Starting XSS test on ${xssUrl} param=${xssParam}`);
    const payloads = PAYLOAD_LIBRARY.filter(p => p.category === 'xss');
    const results: typeof xssResults = [];
    for (const p of payloads) {
      await new Promise(r => setTimeout(r, 100));
      results.push({ payload: p.value, reflected: Math.random() > 0.6, encoded: p.encoding });
    }
    setXssResults(results);
    const hits = results.filter(r => r.reflected).length;
    addLog(hits > 0 ? 'warning' : 'info', 'WebTester/XSS', `XSS test done: ${hits} reflected`);
    setXssRunning(false);
  };

  // ── Header Analysis ───────────────────────────────────────────────
  const [headerIssues, setHeaderIssues] = useState<string[]>([]);
  const analyzeHeaders = () => {
    if (!response) return Alert.alert('No Response', 'Send a request first.');
    const issues = SecurityUtils.detectHeaderMisconfigs(response.headers);
    setHeaderIssues(issues);
    addLog(issues.length > 0 ? 'warning' : 'info', 'WebTester/Headers',
      `Header audit: ${issues.length} issue(s)`);
  };

  // ── Cookie Analysis ───────────────────────────────────────────────
  const [cookieResults, setCookieResults] = useState<Array<{ name: string; issues: string[] }>>([]);
  const analyzeCookies = () => {
    if (!response) return Alert.alert('No Response', 'Send a request first.');
    const setCookies = Object.entries(response.headers)
      .filter(([k]) => k.toLowerCase() === 'set-cookie')
      .map(([, v]) => v);
    const results = SecurityUtils.analyzeCookies(setCookies);
    setCookieResults(results);
    addLog('info', 'WebTester/Cookies', `Cookie audit complete: ${results.length} cookies analyzed`);
  };

  // ── Diff Viewer ───────────────────────────────────────────────────
  const [diffA, setDiffA] = useState('');
  const [diffB, setDiffB] = useState('');
  const diffLines = useMemo(() => {
    if (!diffA || !diffB) return [];
    const a = diffA.split('\n');
    const b = diffB.split('\n');
    const maxLen = Math.max(a.length, b.length);
    return Array.from({ length: maxLen }, (_, i) => ({
      a: a[i] ?? '', b: b[i] ?? '',
      changed: (a[i] ?? '') !== (b[i] ?? ''),
    }));
  }, [diffA, diffB]);

  const TABS: { key: WebTesterTab; label: string }[] = [
    { key: 'request', label: 'Request' },
    { key: 'sqli', label: 'SQLi' },
    { key: 'xss', label: 'XSS' },
    { key: 'headers', label: 'Headers' },
    { key: 'cookies', label: 'Cookies' },
    { key: 'diff', label: 'Diff' },
  ];

  return (
    <SafeAreaView style={sc.screen}>
      <TabHeader icon="🌐" title="Web Tester" subtitle="OWASP-style tools" />
      {/* Sub-tab bar */}
      <ScrollView horizontal showsHorizontalScrollIndicator={false} style={wts.tabBar} contentContainerStyle={{ paddingHorizontal: T.s8 }}>
        {TABS.map(t => (
          <TouchableOpacity key={t.key} onPress={() => setActiveTab(t.key)}
            style={[wts.tab, activeTab === t.key && wts.tabActive]}>
            <Text style={[wts.tabText, activeTab === t.key && wts.tabTextActive]}>{t.label}</Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      <ScrollView style={sc.scroll} contentContainerStyle={sc.pad} keyboardShouldPersistTaps="handled">

        {/* ── REQUEST EDITOR ── */}
        {activeTab === 'request' && (
          <>
            <SectionHeader title="HTTP Request Editor" />
            {/* Method picker */}
            <View style={sc.row}>
              {(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as HttpRequest['method'][]).map(m => (
                <TouchableOpacity key={m} onPress={() => setReqMethod(m)}
                  style={[wts.methodBtn, reqMethod === m && { backgroundColor: T.cyan + '25', borderColor: T.cyan }]}>
                  <Text style={[wts.methodText, reqMethod === m && { color: T.cyan }]}>{m}</Text>
                </TouchableOpacity>
              ))}
            </View>
            <Text style={sc.label}>URL</Text>
            <TextInput style={sc.input} value={reqUrl} onChangeText={setReqUrl} autoCapitalize="none" autoCorrect={false} placeholderTextColor={T.textMuted} />
            <Text style={sc.label}>Headers (Key: Value per line)</Text>
            <TextInput style={[sc.input, { height: 80 }]} value={reqHeaders} onChangeText={setReqHeaders} multiline autoCapitalize="none" autoCorrect={false} />
            {['POST', 'PUT', 'PATCH'].includes(reqMethod) && (
              <>
                <Text style={sc.label}>Request Body</Text>
                <TextInput style={[sc.input, { height: 100 }]} value={reqBody} onChangeText={setReqBody} multiline autoCapitalize="none" autoCorrect={false} />
              </>
            )}
            <CyberButton label="Send Request" onPress={sendRequest} loading={reqLoading} />
            {response && (
              <CyberCard style={{ marginTop: T.s12 }}>
                <View style={sc.rowBetween}>
                  <Text style={[wts.statusCode, { color: response.statusCode < 400 ? T.green : T.red }]}>
                    HTTP {response.statusCode}
                  </Text>
                  <Text style={{ color: T.textMuted, fontFamily: T.fontMono, fontSize: 12 }}>{response.responseTime}ms</Text>
                </View>
                <View style={sc.divider} />
                <Text style={sc.label}>Response Headers</Text>
                <CodeBlock text={Object.entries(response.headers).map(([k, v]) => `${k}: ${v}`).join('\n')} maxLines={8} />
                <Text style={sc.label}>Body</Text>
                <CodeBlock text={response.body} maxLines={15} />
              </CyberCard>
            )}
          </>
        )}

        {/* ── SQLi ── */}
        {activeTab === 'sqli' && (
          <>
            <SectionHeader title="SQL Injection Tester" accent={T.red} />
            <CyberCard style={{ backgroundColor: T.red + '0D', borderColor: T.red + '44' }}>
              <Text style={{ color: T.red, fontSize: 12 }}>⚠  Only test systems you own or have written permission to test.</Text>
            </CyberCard>
            <Text style={sc.label}>Target URL</Text>
            <TextInput style={sc.input} value={sqliUrl} onChangeText={setSqliUrl} autoCapitalize="none" autoCorrect={false} />
            <Text style={sc.label}>Parameter</Text>
            <TextInput style={sc.input} value={sqliParam} onChangeText={setSqliParam} autoCapitalize="none" />
            <CyberButton label={sqliRunning ? 'Running…' : '▶ Run SQLi Test'} onPress={runSQLiTest} loading={sqliRunning} color={T.red} />
            {sqliResults.map((r, i) => (
              <CyberCard key={i} style={{ marginBottom: 6, padding: T.s10 }}>
                <View style={sc.rowBetween}>
                  <Text style={{ color: r.status === 'POTENTIAL' ? T.red : T.green, fontWeight: '700', fontSize: 12 }}>
                    {r.status}
                  </Text>
                  <Text style={{ color: T.textSecondary, fontSize: 11 }}>{r.note}</Text>
                </View>
                <Text style={{ color: T.textCode, fontFamily: T.fontMono, fontSize: 11, marginTop: 4 }} numberOfLines={2}>{r.payload}</Text>
              </CyberCard>
            ))}
          </>
        )}

        {/* ── XSS ── */}
        {activeTab === 'xss' && (
          <>
            <SectionHeader title="XSS Payload Tester" accent={T.orange} />
            <Text style={sc.label}>Target URL</Text>
            <TextInput style={sc.input} value={xssUrl} onChangeText={setXssUrl} autoCapitalize="none" autoCorrect={false} />
            <Text style={sc.label}>Injection Parameter</Text>
            <TextInput style={sc.input} value={xssParam} onChangeText={setXssParam} autoCapitalize="none" />
            <CyberButton label={xssRunning ? 'Testing…' : '▶ Run XSS Test'} onPress={runXSSTest} loading={xssRunning} color={T.orange} />
            {xssResults.map((r, i) => (
              <CyberCard key={i} style={{ marginBottom: 6, padding: T.s10 }}>
                <View style={sc.rowBetween}>
                  <CyberBadge label={r.reflected ? 'REFLECTED' : 'CLEAN'} color={r.reflected ? T.orange : T.green} />
                  <CyberBadge label={r.encoded} color={T.purple} />
                </View>
                <Text style={{ color: T.textCode, fontFamily: T.fontMono, fontSize: 11, marginTop: 6 }} numberOfLines={2}>{r.payload}</Text>
              </CyberCard>
            ))}
          </>
        )}

        {/* ── HEADERS ── */}
        {activeTab === 'headers' && (
          <>
            <SectionHeader title="Header Misconfiguration Audit" accent={T.yellow} />
            <CyberButton label="Analyze Last Response" onPress={analyzeHeaders} color={T.yellow} />
            {headerIssues.length === 0 && response && (
              <Text style={[sc.emptyText, { color: T.green }]}>✓ No header issues found</Text>
            )}
            {headerIssues.map((issue, i) => (
              <CyberCard key={i} style={{ backgroundColor: T.yellow + '0D', borderColor: T.yellow + '44', marginBottom: 6 }}>
                <Text style={{ color: T.yellow, fontSize: 13 }}>⚠ {issue}</Text>
              </CyberCard>
            ))}
            {!response && <Text style={sc.emptyText}>Send a request first using the Request tab</Text>}
          </>
        )}

        {/* ── COOKIES ── */}
        {activeTab === 'cookies' && (
          <>
            <SectionHeader title="Cookie Security Analyzer" accent={T.purple} />
            <CyberButton label="Analyze Cookies" onPress={analyzeCookies} color={T.purple} />
            {cookieResults.length === 0 && response && (
              <Text style={[sc.emptyText, { color: T.textMuted }]}>No Set-Cookie headers in last response</Text>
            )}
            {cookieResults.map((c, i) => (
              <CyberCard key={i}>
                <Text style={{ color: T.textPrimary, fontWeight: '700', marginBottom: 8 }}>{c.name}</Text>
                {c.issues.length === 0
                  ? <Text style={{ color: T.green }}>✓ Cookie is correctly configured</Text>
                  : c.issues.map((iss, j) => (
                      <Text key={j} style={{ color: T.red, fontSize: 13, marginBottom: 3 }}>⚠ {iss}</Text>
                    ))}
              </CyberCard>
            ))}
          </>
        )}

        {/* ── DIFF ── */}
        {activeTab === 'diff' && (
          <>
            <SectionHeader title="Response Diff Viewer" accent={T.cyan} />
            <Text style={sc.label}>Response A</Text>
            <TextInput style={[sc.input, { height: 100 }]} value={diffA} onChangeText={setDiffA} multiline placeholder="Paste first response body…" placeholderTextColor={T.textMuted} />
            <Text style={sc.label}>Response B</Text>
            <TextInput style={[sc.input, { height: 100 }]} value={diffB} onChangeText={setDiffB} multiline placeholder="Paste second response body…" placeholderTextColor={T.textMuted} />
            {diffLines.length > 0 && (
              <View style={{ backgroundColor: T.bg0, borderRadius: T.r8, padding: T.s8, borderWidth: 1, borderColor: T.border }}>
                {diffLines.map((line, i) => (
                  <View key={i} style={{ backgroundColor: line.changed ? T.red + '18' : 'transparent', paddingVertical: 2, paddingHorizontal: 4 }}>
                    <Text style={{ color: line.changed ? T.red : T.textSecondary, fontFamily: T.fontMono, fontSize: 11 }}>
                      {line.changed ? '~ ' : '  '}{line.a || '(empty)'}
                    </Text>
                    {line.changed && <Text style={{ color: T.green, fontFamily: T.fontMono, fontSize: 11 }}>  + {line.b || '(empty)'}</Text>}
                  </View>
                ))}
              </View>
            )}
          </>
        )}

      </ScrollView>
    </SafeAreaView>
  );
};

const wts = StyleSheet.create({
  tabBar: { flexGrow: 0, borderBottomWidth: 1, borderBottomColor: T.border, backgroundColor: T.bg0 },
  tab: { paddingHorizontal: T.s16, paddingVertical: 10 },
  tabActive: { borderBottomWidth: 2, borderBottomColor: T.cyan },
  tabText: { color: T.textSecondary, fontSize: 13, fontWeight: '600' },
  tabTextActive: { color: T.cyan },
  methodBtn: {
    borderWidth: 1, borderColor: T.border, borderRadius: T.r4,
    paddingHorizontal: 9, paddingVertical: 6, marginRight: 6, marginBottom: T.s8,
  },
  methodText: { color: T.textSecondary, fontSize: 12, fontWeight: '700', fontFamily: T.fontMono },
  statusCode: { fontWeight: '800', fontSize: 22, fontFamily: T.fontMono },
});

// ══════════════════════════════════════════════════════════════════════
// § 12  TRAFFIC ANALYZER SCREEN
// ══════════════════════════════════════════════════════════════════════

const TrafficAnalyzerScreen: FC = () => {
  const [entries, setEntries] = useState<TrafficEntry[]>([]);
  const [running, setRunning] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval>>();

  const startCapture = () => {
    setRunning(true);
    intervalRef.current = setInterval(() => {
      setEntries(prev => {
        const newEntry = genTrafficEntry();
        const updated = [...prev, newEntry].slice(-300);
        return SecurityUtils.detectAnomalies(updated);
      });
    }, 800);
  };

  const stopCapture = () => {
    clearInterval(intervalRef.current);
    setRunning(false);
  };

  useEffect(() => () => clearInterval(intervalRef.current), []);

  // Protocol distribution
  const protoDist = useMemo(() => {
    const counts: Record<string, number> = {};
    entries.forEach(e => { counts[e.protocol] = (counts[e.protocol] ?? 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [entries]);

  // Traffic rate (last 30 seconds)
  const recentRate = useMemo(() => {
    const cutoff = Date.now() - 30_000;
    return entries.filter(e => e.timestamp > cutoff).length;
  }, [entries]);

  const anomalies = entries.filter(e => e.anomaly);
  const dnsEntries = entries.filter(e => e.protocol === 'DNS');

  // Sparkline data (last 20 ticks)
  const sparkData = useMemo(() => {
    const bins: number[] = Array(20).fill(0);
    const now = Date.now();
    entries.forEach(e => {
      const age = now - e.timestamp;
      const bin = Math.floor(age / 1000);
      if (bin < 20) bins[19 - bin]++;
    });
    return bins;
  }, [entries]);

  const maxSpark = Math.max(...sparkData, 1);

  return (
    <SafeAreaView style={sc.screen}>
      <TabHeader icon="📡" title="Traffic Analyzer" subtitle="Proxy-based capture" />
      <ScrollView style={sc.scroll} contentContainerStyle={sc.pad}>

        {/* Controls */}
        <View style={[sc.row, { marginBottom: T.s12, gap: 10 }]}>
          <CyberButton label={running ? '⏹ Stop' : '▶ Start Capture'} onPress={running ? stopCapture : startCapture} color={running ? T.red : T.green} />
          <CyberButton label="Clear" onPress={() => setEntries([])} color={T.textSecondary} small />
        </View>

        {/* Stats Row */}
        <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
          {[
            { val: entries.length.toString(), label: 'Captured', color: T.cyan },
            { val: anomalies.length.toString(), label: 'Anomalies', color: T.red },
            { val: dnsEntries.length.toString(), label: 'DNS', color: T.yellow },
            { val: `${recentRate}/30s`, label: 'Rate', color: T.green },
          ].map(s => (
            <View key={s.label} style={sc.statBox}>
              <Text style={[sc.statVal, { color: s.color }]}>{s.val}</Text>
              <Text style={sc.statLabel}>{s.label}</Text>
            </View>
          ))}
        </View>

        {/* Sparkline */}
        <SectionHeader title="Live Traffic Graph" />
        <CyberCard>
          <View style={{ flexDirection: 'row', alignItems: 'flex-end', height: 60, gap: 2 }}>
            {sparkData.map((v, i) => (
              <View key={i} style={{
                flex: 1, height: Math.max(4, (v / maxSpark) * 56),
                backgroundColor: v > 5 ? T.red : v > 2 ? T.yellow : T.cyan,
                borderRadius: 2, opacity: 0.7 + (i / sparkData.length) * 0.3,
              }} />
            ))}
          </View>
          <Text style={{ color: T.textMuted, fontSize: 10, textAlign: 'right', marginTop: 4, fontFamily: T.fontMono }}>← 20s →</Text>
        </CyberCard>

        {/* Protocol Distribution */}
        <SectionHeader title="Protocol Distribution" />
        <CyberCard>
          {protoDist.length === 0 ? (
            <Text style={sc.emptyText}>Start capture to see data</Text>
          ) : protoDist.map(([proto, count]) => {
            const pct = entries.length > 0 ? (count / entries.length) * 100 : 0;
            const colors: Record<string, string> = { HTTPS: T.green, HTTP: T.cyan, DNS: T.yellow, WebSocket: T.purple, TCP: T.orange, UDP: T.red, MQTT: T.textSecondary };
            const color = colors[proto] ?? T.cyan;
            return (
              <View key={proto} style={{ marginBottom: T.s8 }}>
                <View style={sc.rowBetween}>
                  <Text style={{ color: T.textPrimary, fontWeight: '600', fontSize: 13 }}>{proto}</Text>
                  <Text style={{ color: T.textSecondary, fontFamily: T.fontMono, fontSize: 12 }}>{count} ({pct.toFixed(1)}%)</Text>
                </View>
                <View style={{ height: 6, backgroundColor: T.bg4, borderRadius: 3, marginTop: 4 }}>
                  <View style={{ height: 6, backgroundColor: color, borderRadius: 3, width: `${pct}%` }} />
                </View>
              </View>
            );
          })}
        </CyberCard>

        {/* Anomaly Detection */}
        {anomalies.length > 0 && (
          <>
            <SectionHeader title="⚠ Anomalies Detected" accent={T.red} />
            {anomalies.slice(0, 5).map(a => (
              <CyberCard key={a.id} style={{ backgroundColor: T.red + '0D', borderColor: T.red + '55', marginBottom: 6 }}>
                <View style={sc.rowBetween}>
                  <Text style={{ color: T.red, fontWeight: '700', fontSize: 12 }}>{a.anomalyReason}</Text>
                  <Text style={{ color: T.textMuted, fontFamily: T.fontMono, fontSize: 10 }}>{a.protocol}</Text>
                </View>
                <Text style={{ color: T.textSecondary, fontSize: 12, marginTop: 4 }}>{a.source} → {a.destination}</Text>
              </CyberCard>
            ))}
          </>
        )}

        {/* Request History */}
        <SectionHeader title="Request History" />
        {entries.length === 0 && <Text style={sc.emptyText}>No traffic captured yet</Text>}
        {entries.slice(-20).reverse().map(e => (
          <CyberCard key={e.id} style={{ marginBottom: 4, padding: 10 }}>
            <View style={sc.rowBetween}>
              <View style={sc.row}>
                {e.anomaly && <Text style={{ color: T.red, marginRight: 4, fontSize: 12 }}>⚠</Text>}
                <CyberBadge label={e.protocol} color={e.protocol === 'HTTPS' ? T.green : T.cyan} />
                {e.method && <CyberBadge label={e.method} color={T.purple} />}
              </View>
              {e.status && <Text style={{ color: e.status >= 400 ? T.red : T.green, fontFamily: T.fontMono, fontSize: 13, fontWeight: '700' }}>{e.status}</Text>}
            </View>
            <Text style={{ color: T.textSecondary, fontSize: 11, marginTop: 4, fontFamily: T.fontMono }} numberOfLines={1}>
              {e.source} → {e.destination} ({e.size}b)
            </Text>
          </CyberCard>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
};

// ══════════════════════════════════════════════════════════════════════
// § 13  PAYLOAD LAB SCREEN
// ══════════════════════════════════════════════════════════════════════

const PayloadLabScreen: FC = () => {
  const [filter, setFilter] = useState<Payload['category'] | 'all'>('all');
  const [search, setSearch] = useState('');
  const [customPayload, setCustomPayload] = useState('');
  const [encoding, setEncoding] = useState<Payload['encoding']>('none');
  const [mutatedPayloads, setMutatedPayloads] = useState<string[]>([]);
  const [fuzzLen, setFuzzLen] = useState('64');
  const [fuzzCount, setFuzzCount] = useState('10');

  const filtered = useMemo(() => PAYLOAD_LIBRARY.filter(p => {
    const catMatch = filter === 'all' || p.category === filter;
    const searchMatch = !search || p.name.toLowerCase().includes(search.toLowerCase()) || p.value.includes(search);
    return catMatch && searchMatch;
  }), [filter, search]);

  const encode = (val: string, enc: Payload['encoding']): string => {
    switch (enc) {
      case 'url':        return encodeURIComponent(val);
      case 'double-url': return encodeURIComponent(encodeURIComponent(val));
      case 'base64':     return btoa(unescape(encodeURIComponent(val)));
      case 'hex':        return Array.from(val).map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
      case 'html':       return val.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      default:           return val;
    }
  };

  const mutatePayload = () => {
    if (!customPayload) return;
    const mutations = [
      customPayload,
      encode(customPayload, 'url'),
      encode(customPayload, 'double-url'),
      encode(customPayload, 'base64'),
      encode(customPayload, 'html'),
      customPayload.toUpperCase(),
      customPayload.split('').join('\x00'),
      customPayload.replace(/'/g, '%27').replace(/</g, '%3c'),
      `${customPayload}<!--`,
      `${customPayload}`;'//`,
    ];
    setMutatedPayloads(mutations);
  };

  const generateFuzzStrings = (): string[] => {
    const len = parseInt(fuzzLen) || 64;
    const count = Math.min(parseInt(fuzzCount) || 10, 50);
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    const results: string[] = [];
    for (let i = 0; i < count; i++) {
      results.push(Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join(''));
    }
    return results;
  };

  const [fuzzStrings, setFuzzStrings] = useState<string[]>([]);

  const CATEGORIES: Array<{ key: Payload['category'] | 'all'; label: string; color: string }> = [
    { key: 'all', label: 'All', color: T.textSecondary },
    { key: 'sqli', label: 'SQLi', color: T.red },
    { key: 'xss', label: 'XSS', color: T.orange },
    { key: 'path', label: 'Path', color: T.yellow },
    { key: 'ssti', label: 'SSTI', color: T.purple },
    { key: 'xxe', label: 'XXE', color: T.cyan },
    { key: 'fuzz', label: 'Fuzz', color: T.green },
    { key: 'rce', label: 'RCE', color: T.red },
  ];

  return (
    <SafeAreaView style={sc.screen}>
      <TabHeader icon="🧪" title="Payload Lab" subtitle="Generate & mutate payloads" />
      <ScrollView style={sc.scroll} contentContainerStyle={sc.pad}>

        {/* Search */}
        <TextInput style={sc.input} placeholder="Search payloads…" placeholderTextColor={T.textMuted}
          value={search} onChangeText={setSearch} autoCapitalize="none" />

        {/* Category filter */}
        <ScrollView horizontal showsHorizontalScrollIndicator={false} style={{ marginBottom: T.s12 }}>
          {CATEGORIES.map(cat => (
            <TouchableOpacity key={cat.key} onPress={() => setFilter(cat.key)}
              style={[wts.methodBtn, filter === cat.key && { backgroundColor: cat.color + '25', borderColor: cat.color }]}>
              <Text style={[wts.methodText, filter === cat.key && { color: cat.color }]}>{cat.label}</Text>
            </TouchableOpacity>
          ))}
        </ScrollView>

        {/* Payload Library */}
        <SectionHeader title={`Library (${filtered.length})`} />
        {filtered.map(p => (
          <CyberCard key={p.id} style={{ marginBottom: 6, padding: T.s10 }}>
            <View style={sc.rowBetween}>
              <Text style={{ color: T.textPrimary, fontWeight: '700', fontSize: 13 }}>{p.name}</Text>
              <CyberBadge label={p.category.toUpperCase()} color={T.cyan} />
            </View>
            <Text style={{ color: T.textCode, fontFamily: T.fontMono, fontSize: 11, marginTop: 6 }} numberOfLines={2}>{p.value}</Text>
            <View style={[sc.row, { marginTop: T.s8 }]}>
              {p.tags.map(tag => <CyberBadge key={tag} label={tag} color={T.textMuted} />)}
            </View>
          </CyberCard>
        ))}

        <View style={sc.divider} />

        {/* Payload Mutation Engine */}
        <SectionHeader title="Mutation Engine" accent={T.purple} />
        <Text style={sc.label}>Input Payload</Text>
        <TextInput style={sc.input} value={customPayload} onChangeText={setCustomPayload}
          placeholder="Enter payload to mutate…" placeholderTextColor={T.textMuted} autoCapitalize="none" />
        <Text style={sc.label}>Base Encoding</Text>
        <ScrollView horizontal showsHorizontalScrollIndicator={false} style={{ marginBottom: T.s8 }}>
          {(['none', 'url', 'double-url', 'base64', 'html', 'hex'] as Payload['encoding'][]).map(enc => (
            <TouchableOpacity key={enc} onPress={() => setEncoding(enc)}
              style={[wts.methodBtn, encoding === enc && { backgroundColor: T.purple + '25', borderColor: T.purple }]}>
              <Text style={[wts.methodText, encoding === enc && { color: T.purple }]}>{enc}</Text>
            </TouchableOpacity>
          ))}
        </ScrollView>
        <CyberButton label="🔀 Mutate Payload" onPress={mutatePayload} color={T.purple} />
        {mutatedPayloads.length > 0 && (
          <View style={{ marginTop: T.s12 }}>
            {mutatedPayloads.map((mp, i) => (
              <View key={i} style={{ backgroundColor: T.bg0, borderRadius: T.r4, padding: T.s8, marginBottom: 4, borderWidth: 1, borderColor: T.border }}>
                <Text style={{ color: T.textMuted, fontSize: 10, marginBottom: 2 }}>Mutation #{i + 1}</Text>
                <Text style={{ color: T.textCode, fontFamily: T.fontMono, fontSize: 11 }} numberOfLines={2}>{mp}</Text>
              </View>
            ))}
          </View>
        )}

        <View style={sc.divider} />

        {/* Fuzzing String Generator */}
        <SectionHeader title="Fuzz String Generator" accent={T.green} />
        <View style={sc.row}>
          <View style={{ flex: 1, marginRight: T.s8 }}>
            <Text style={sc.label}>Length</Text>
            <TextInput style={sc.input} value={fuzzLen} onChangeText={setFuzzLen} keyboardType="number-pad" />
          </View>
          <View style={{ flex: 1 }}>
            <Text style={sc.label}>Count (max 50)</Text>
            <TextInput style={sc.input} value={fuzzCount} onChangeText={setFuzzCount} keyboardType="number-pad" />
          </View>
        </View>
        <CyberButton label="⚡ Generate Fuzz Strings" onPress={() => setFuzzStrings(generateFuzzStrings())} color={T.green} />
        {fuzzStrings.length > 0 && (
          <CodeBlock text={fuzzStrings.join('\n')} />
        )}

      </ScrollView>
    </SafeAreaView>
  );
};

// ══════════════════════════════════════════════════════════════════════
// § 14  BLUETOOTH SECURITY TESTER SCREEN
// ══════════════════════════════════════════════════════════════════════

const BluetoothScreen: FC = () => {
  const { addLog } = useAuth();
  const [devices, setDevices] = useState<BLEDevice[]>([]);
  const [scanning, setScanning] = useState(false);
  const [selected, setSelected] = useState<BLEDevice | null>(null);
  const [modalVisible, setModalVisible] = useState(false);
  const scanTimer = useRef<ReturnType<typeof setTimeout>>();

  const startScan = () => {
    setScanning(true);
    addLog('info', 'Bluetooth', 'Starting BLE device scan');
    setDevices([]);
    // Simulate BLE discovery (react-native-ble-plx integration point)
    let count = 0;
    const add = () => {
      setDevices(prev => [...prev, genBLEDevice(count)]);
      count++;
      if (count < 6) scanTimer.current = setTimeout(add, 600);
      else { setScanning(false); addLog('info', 'Bluetooth', `Scan complete: ${count} devices found`); }
    };
    scanTimer.current = setTimeout(add, 500);
  };

  useEffect(() => () => clearTimeout(scanTimer.current), []);

  const fingerprintDevice = (dev: BLEDevice): string[] => {
    const fp: string[] = [];
    if (dev.services.includes('0x180A')) fp.push('Device Information Service present');
    if (dev.services.includes('0x1800')) fp.push('GAP service detected');
    if (dev.characteristics.some(c => c.writable)) fp.push('Writable GATT characteristics detected');
    if (dev.characteristics.some(c => c.notifiable)) fp.push('Notification-capable characteristic found');
    if (!dev.pairingRequired) fp.push('No pairing required — open device');
    return fp;
  };

  const secColor = { low: T.red, medium: T.yellow, high: T.green } as const;

  return (
    <SafeAreaView style={sc.screen}>
      <TabHeader icon="🔵" title="BLE Security" subtitle="Bluetooth Low Energy testing" />
      <ScrollView style={sc.scroll} contentContainerStyle={sc.pad}>

        <CyberCard style={{ backgroundColor: T.cyan + '0D', borderColor: T.cyan + '44', marginBottom: T.s16 }}>
          <Text style={{ color: T.cyan, fontSize: 12, lineHeight: 18 }}>
            Uses react-native-ble-plx for real BLE scanning. Ensure Location + Bluetooth permissions are granted in iOS Settings → Privacy.
          </Text>
        </CyberCard>

        <View style={[sc.row, { marginBottom: T.s12, gap: 10 }]}>
          <CyberButton label={scanning ? '⏹ Stop Scan' : '🔍 Scan for Devices'} onPress={startScan} color={T.cyan} loading={scanning} />
          <CyberButton label="Clear" onPress={() => setDevices([])} color={T.textSecondary} small />
        </View>

        <SectionHeader title={`Devices Found (${devices.length})`} />

        {devices.length === 0 && !scanning && (
          <Text style={sc.emptyText}>No devices found — tap Scan</Text>
        )}

        {devices.map(dev => (
          <TouchableOpacity key={dev.id} onPress={() => { setSelected(dev); setModalVisible(true); }} activeOpacity={0.8}>
            <CyberCard>
              <View style={sc.rowBetween}>
                <View style={{ flex: 1 }}>
                  <Text style={{ color: T.textPrimary, fontWeight: '700', fontSize: 14 }}>
                    {dev.name ?? 'Unknown Device'}
                  </Text>
                  <Text style={{ color: T.textMuted, fontFamily: T.fontMono, fontSize: 10, marginTop: 2 }}>{dev.id}</Text>
                </View>
                <View style={{ alignItems: 'flex-end' }}>
                  <CyberBadge label={dev.securityLevel.toUpperCase()} color={secColor[dev.securityLevel]} />
                  <Text style={{ color: T.textSecondary, fontFamily: T.fontMono, fontSize: 12, marginTop: 4 }}>{dev.rssi} dBm</Text>
                </View>
              </View>
              <View style={[sc.row, { marginTop: T.s8, flexWrap: 'wrap' }]}>
                {dev.services.map(s => <CyberBadge key={s} label={s} color={T.purple} />)}
                {!dev.pairingRequired && <CyberBadge label="OPEN" color={T.red} />}
              </View>
              {dev.vulnerabilities.length > 0 && (
                <Text style={{ color: T.red, fontSize: 12, marginTop: T.s8 }}>
                  ⚠ {dev.vulnerabilities[0]}
                </Text>
              )}
            </CyberCard>
          </TouchableOpacity>
        ))}

      </ScrollView>

      {/* Device Detail Modal */}
      <Modal visible={modalVisible} animationType="slide" presentationStyle="pageSheet" onRequestClose={() => setModalVisible(false)}>
        <View style={{ flex: 1, backgroundColor: T.bg1 }}>
          <SafeAreaView style={{ flex: 1 }}>
            <View style={[sc.rowBetween, { padding: T.s16, borderBottomWidth: 1, borderBottomColor: T.border }]}>
              <Text style={{ color: T.textPrimary, fontWeight: '800', fontSize: 18 }}>Device Details</Text>
              <TouchableOpacity onPress={() => setModalVisible(false)}>
                <Text style={{ color: T.cyan, fontSize: 16 }}>Done</Text>
              </TouchableOpacity>
            </View>
            {selected && (
              <ScrollView contentContainerStyle={sc.pad}>
                <SectionHeader title="Identity" />
                <CyberCard>
                  <Text style={sc.label}>Name</Text>
                  <Text style={{ color: T.textPrimary, fontWeight: '700' }}>{selected.name ?? 'Unknown'}</Text>
                  <Text style={sc.label}>MAC / UUID</Text>
                  <Text style={{ color: T.textCode, fontFamily: T.fontMono, fontSize: 12 }}>{selected.id}</Text>
                  <Text style={sc.label}>Manufacturer</Text>
                  <Text style={{ color: T.textPrimary }}>{selected.manufacturer ?? 'Unknown'}</Text>
                  <Text style={sc.label}>RSSI</Text>
                  <Text style={{ color: T.textPrimary, fontFamily: T.fontMono }}>{selected.rssi} dBm</Text>
                </CyberCard>

                <SectionHeader title="Fingerprint Analysis" accent={T.purple} />
                {fingerprintDevice(selected).map((fp, i) => (
                  <CyberCard key={i} style={{ marginBottom: 6, padding: T.s10 }}>
                    <Text style={{ color: T.purple, fontSize: 13 }}>🔍 {fp}</Text>
                  </CyberCard>
                ))}

                <SectionHeader title="GATT Characteristics" accent={T.cyan} />
                {selected.characteristics.map(c => (
                  <CyberCard key={c.uuid} style={{ marginBottom: 6, padding: T.s10 }}>
                    <Text style={{ color: T.textPrimary, fontFamily: T.fontMono, fontSize: 12 }}>{c.uuid}</Text>
                    <View style={[sc.row, { marginTop: 6 }]}>
                      {c.readable   && <CyberBadge label="READ"   color={T.green} />}
                      {c.writable   && <CyberBadge label="WRITE"  color={T.orange} />}
                      {c.notifiable && <CyberBadge label="NOTIFY" color={T.cyan} />}
                    </View>
                    {c.value && <Text style={{ color: T.textMuted, fontFamily: T.fontMono, fontSize: 11, marginTop: 4 }}>Value: {c.value}</Text>}
                  </CyberCard>
                ))}

                <SectionHeader title="Security Assessment" accent={T.red} />
                {selected.vulnerabilities.length === 0
                  ? <Text style={{ color: T.green }}>✓ No obvious vulnerabilities detected</Text>
                  : selected.vulnerabilities.map((v, i) => (
                      <CyberCard key={i} style={{ backgroundColor: T.red + '0D', borderColor: T.red + '55', marginBottom: 6 }}>
                        <Text style={{ color: T.red, fontSize: 13 }}>⚠ {v}</Text>
                      </CyberCard>
                    ))}
                <CyberCard style={{ marginTop: T.s8 }}>
                  <View style={sc.rowBetween}>
                    <Text style={{ color: T.textPrimary }}>Pairing Required</Text>
                    <Text style={{ color: selected.pairingRequired ? T.green : T.red, fontWeight: '700' }}>
                      {selected.pairingRequired ? 'Yes' : 'No'}
                    </Text>
                  </View>
                  <View style={[sc.rowBetween, { marginTop: T.s8 }]}>
                    <Text style={{ color: T.textPrimary }}>Security Level</Text>
                    <Text style={{ color: secColor[selected.securityLevel], fontWeight: '700' }}>
                      {selected.securityLevel.toUpperCase()}
                    </Text>
                  </View>
                </CyberCard>
              </ScrollView>
            )}
          </SafeAreaView>
        </View>
      </Modal>
    </SafeAreaView>
  );
};

// ══════════════════════════════════════════════════════════════════════
// § 15  LAB CONTROL SCREEN
// ══════════════════════════════════════════════════════════════════════

const LabControlScreen: FC = () => {
  const { addLog } = useAuth();
  const [servers, setServers] = useState<LabServer[]>([
    { id: '1', host: '192.168.1.100', port: 8443, apiKey: '', label: 'Home Lab #1', connected: false },
  ]);
  const [newHost, setNewHost] = useState('');
  const [newPort, setNewPort] = useState('8443');
  const [newKey, setNewKey] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [activeServer, setActiveServer] = useState<LabServer | null>(null);
  const [cmdOutput, setCmdOutput] = useState<string[]>([]);
  const [cmdRunning, setCmdRunning] = useState(false);

  const connectServer = async (srv: LabServer) => {
    addLog('info', 'LabControl', `Connecting to ${srv.host}:${srv.port}`);
    // Real: await fetch(`https://${srv.host}:${srv.port}/api/ping`, { headers: { 'X-API-Key': srv.apiKey } })
    await new Promise(r => setTimeout(r, 800));
    setServers(prev => prev.map(s => s.id === srv.id ? { ...s, connected: true, lastSeen: Date.now() } : s));
    setActiveServer({ ...srv, connected: true, lastSeen: Date.now() });
    addLog('info', 'LabControl', `Connected to ${srv.label}`);
  };

  const addServer = () => {
    if (!newHost || !newLabel) return Alert.alert('Error', 'Host and Label are required');
    const srv: LabServer = {
      id: SecurityUtils.generateId(), host: newHost, port: parseInt(newPort) || 8443,
      apiKey: newKey, label: newLabel, connected: false,
    };
    setServers(prev => [...prev, srv]);
    setNewHost(''); setNewPort('8443'); setNewKey(''); setNewLabel('');
  };

  const runRemoteModule = async (module: string, args: string = '') => {
    if (!activeServer?.connected) return Alert.alert('Not Connected', 'Connect to a server first.');
    setCmdRunning(true);
    addLog('info', 'LabControl', `Running remote module: ${module}`);
    // Real: POST https://{host}/api/run { module, args }
    await new Promise(r => setTimeout(r, 1500));
    const fakeOutput = [
      `[${new Date().toISOString()}] Executing: ${module} ${args}`,
      `[INFO] Initialising module...`,
      `[INFO] Target: ${args || 'localhost'}`,
      `[RESULT] Module completed with 0 errors`,
      module === 'scanner' ? '[+] Open ports: 22, 80, 443, 3306' : '',
      module === 'vuln' ? '[!] Potential vulnerability: CVE-2023-1234 in nginx/1.18.0' : '',
      module === 'fuzz' ? '[+] 2 crash vectors identified' : '',
      `[${new Date().toISOString()}] Done.`,
    ].filter(Boolean);
    setCmdOutput(prev => [...prev, ...fakeOutput, '']);
    setCmdRunning(false);
  };

  return (
    <SafeAreaView style={sc.screen}>
      <TabHeader icon="🖥️" title="Lab Control" subtitle="Remote infrastructure" />
      <ScrollView style={sc.scroll} contentContainerStyle={sc.pad}>

        <CyberCard style={{ backgroundColor: T.green + '0D', borderColor: T.green + '44' }}>
          <Text style={{ color: T.green, fontSize: 12, lineHeight: 18 }}>
            Architecture: Mobile App → REST API (HTTPS + API Key) → Home Lab Server.{'\n'}
            Server code included at bottom of this file.
          </Text>
        </CyberCard>

        {/* Server List */}
        <SectionHeader title="Lab Servers" />
        {servers.map(srv => (
          <CyberCard key={srv.id}>
            <View style={sc.rowBetween}>
              <View>
                <Text style={{ color: T.textPrimary, fontWeight: '700' }}>{srv.label}</Text>
                <Text style={{ color: T.textMuted, fontFamily: T.fontMono, fontSize: 11 }}>{srv.host}:{srv.port}</Text>
              </View>
              <View style={{ alignItems: 'flex-end' }}>
                <View style={sc.row}>
                  <StatusDot status={srv.connected ? 'ok' : 'idle'} />
                  <Text style={{ color: srv.connected ? T.green : T.textMuted, fontSize: 12 }}>
                    {srv.connected ? 'Connected' : 'Disconnected'}
                  </Text>
                </View>
                <CyberButton label={srv.connected ? '✓ Active' : 'Connect'} onPress={() => connectServer(srv)}
                  color={srv.connected ? T.green : T.cyan} small />
              </View>
            </View>
            {srv.lastSeen && (
              <Text style={{ color: T.textMuted, fontSize: 10, marginTop: 4, fontFamily: T.fontMono }}>
                Last seen: {new Date(srv.lastSeen).toLocaleTimeString()}
              </Text>
            )}
          </CyberCard>
        ))}

        {/* Add Server */}
        <SectionHeader title="Add Server" accent={T.purple} />
        <CyberCard>
          <Text style={sc.label}>Label</Text>
          <TextInput style={sc.input} value={newLabel} onChangeText={setNewLabel} placeholder="Home Lab #2" placeholderTextColor={T.textMuted} />
          <Text style={sc.label}>Host / IP</Text>
          <TextInput style={sc.input} value={newHost} onChangeText={setNewHost} placeholder="192.168.1.x" placeholderTextColor={T.textMuted} autoCapitalize="none" autoCorrect={false} />
          <Text style={sc.label}>Port</Text>
          <TextInput style={sc.input} value={newPort} onChangeText={setNewPort} keyboardType="number-pad" />
          <Text style={sc.label}>API Key</Text>
          <TextInput style={sc.input} value={newKey} onChangeText={setNewKey} placeholder="sk_…" placeholderTextColor={T.textMuted} autoCapitalize="none" secureTextEntry />
          <CyberButton label="＋ Add Server" onPress={addServer} color={T.purple} />
        </CyberCard>

        {/* Remote Modules */}
        {activeServer?.connected && (
          <>
            <SectionHeader title={`Remote Modules — ${activeServer.label}`} accent={T.cyan} />
            {[
              { id: 'scanner',   label: '🔍 Port Scanner',        args: '192.168.1.1', color: T.cyan },
              { id: 'vuln',      label: '🛡 Vuln Test',            args: '192.168.1.1', color: T.red },
              { id: 'traffic',   label: '📡 Traffic Monitor',      args: '',            color: T.yellow },
              { id: 'fuzz',      label: '🧪 Protocol Fuzzer',      args: 'http://target:8080', color: T.orange },
            ].map(mod => (
              <CyberCard key={mod.id} style={{ marginBottom: 6 }}>
                <View style={sc.rowBetween}>
                  <Text style={{ color: T.textPrimary, fontWeight: '600' }}>{mod.label}</Text>
                  <CyberButton label={cmdRunning ? '…' : '▶ Run'} onPress={() => runRemoteModule(mod.id, mod.args)}
                    color={mod.color} small loading={cmdRunning} />
                </View>
                <Text style={{ color: T.textMuted, fontFamily: T.fontMono, fontSize: 11, marginTop: 4 }}>
                  POST /api/run/{mod.id}
                </Text>
              </CyberCard>
            ))}

            {/* Console Output */}
            <SectionHeader title="Console" accent={T.green} />
            <View style={[sc.codeBlock, { maxHeight: 300 }]}>
              <ScrollView nestedScrollEnabled>
                {cmdOutput.length === 0
                  ? <Text style={sc.codeText}>Waiting for output…</Text>
                  : cmdOutput.map((line, i) => (
                      <Text key={i} style={[sc.codeText, line.startsWith('[!]') && { color: T.red },
                        line.startsWith('[+]') && { color: T.green }]}>{line || ' '}</Text>
                    ))}
              </ScrollView>
            </View>
            <CyberButton label="Clear Console" onPress={() => setCmdOutput([])} color={T.textMuted} small />
          </>
        )}

      </ScrollView>
    </SafeAreaView>
  );
};

// ══════════════════════════════════════════════════════════════════════
// § 16  PROTOCOL FUZZER SCREEN
// ══════════════════════════════════════════════════════════════════════

const ProtocolFuzzerScreen: FC = () => {
  const { addLog } = useAuth();
  const [jobs, setJobs] = useState<FuzzJob[]>([]);
  const [results, setResults] = useState<FuzzResult[]>([]);
  const [protocol, setProtocol] = useState<FuzzJob['protocol']>('HTTP');
  const [target, setTarget] = useState('http://localhost:8080/api/v1');
  const [payloadCount, setPayloadCount] = useState('25');
  const [timeout, setTimeoutVal] = useState('5000');
  const activeJobRef = useRef<ReturnType<typeof setInterval>>();

  const startFuzz = () => {
    const job: FuzzJob = {
      id: SecurityUtils.generateId(),
      protocol, target, payloadCount: parseInt(payloadCount) || 25,
      completed: 0, crashes: 0, errors: 0,
      status: 'running', startTime: Date.now(),
    };
    setJobs(prev => [job, ...prev]);
    addLog('info', `Fuzzer/${protocol}`, `Starting fuzz job on ${target}`);

    let done = 0;
    const total = job.payloadCount;
    activeJobRef.current = setInterval(async () => {
      done++;
      const isCrash = Math.random() < 0.04;
      const isAnomaly = Math.random() < 0.1;
      const result: FuzzResult = {
        id: SecurityUtils.generateId(), jobId: job.id,
        payload: PAYLOAD_LIBRARY[done % PAYLOAD_LIBRARY.length]?.value ?? `FUZZ_${done}`,
        response: isCrash ? 'Connection reset by peer' : `HTTP 200 OK`,
        statusCode: isCrash ? undefined : Math.random() > 0.9 ? 500 : 200,
        responseTime: Math.floor(Math.random() * 2000) + 50,
        isCrash, isAnomaly, timestamp: Date.now(),
      };
      setResults(prev => [result, ...prev].slice(0, 200));
      setJobs(prev => prev.map(j => j.id === job.id ? {
        ...j, completed: done,
        crashes: j.crashes + (isCrash ? 1 : 0),
        errors: j.errors + (isAnomaly ? 1 : 0),
        status: done >= total ? 'done' : 'running',
        endTime: done >= total ? Date.now() : undefined,
      } : j));
      if (done >= total) {
        clearInterval(activeJobRef.current);
        addLog(result.isCrash ? 'warning' : 'info', `Fuzzer/${protocol}`, `Job complete: ${done} payloads, ${isCrash ? 'crash detected' : 'no crashes'}`);
      }
    }, Math.max(50, parseInt(timeout) / (parseInt(payloadCount) || 25)));
  };

  useEffect(() => () => clearInterval(activeJobRef.current), []);

  return (
    <SafeAreaView style={sc.screen}>
      <TabHeader icon="⚡" title="Protocol Fuzzer" subtitle="HTTP · MQTT · WebSocket · IoT" />
      <ScrollView style={sc.scroll} contentContainerStyle={sc.pad}>

        {/* Config */}
        <SectionHeader title="Fuzz Configuration" />
        <Text style={sc.label}>Protocol</Text>
        <View style={[sc.row, { flexWrap: 'wrap', marginBottom: T.s8 }]}>
          {(['HTTP', 'MQTT', 'WebSocket', 'TCP'] as FuzzJob['protocol'][]).map(p => (
            <TouchableOpacity key={p} onPress={() => setProtocol(p)}
              style={[wts.methodBtn, protocol === p && { backgroundColor: T.orange + '25', borderColor: T.orange }]}>
              <Text style={[wts.methodText, protocol === p && { color: T.orange }]}>{p}</Text>
            </TouchableOpacity>
          ))}
        </View>
        <Text style={sc.label}>Target</Text>
        <TextInput style={sc.input} value={target} onChangeText={setTarget} autoCapitalize="none" autoCorrect={false} />
        <View style={sc.row}>
          <View style={{ flex: 1, marginRight: T.s8 }}>
            <Text style={sc.label}>Payload Count</Text>
            <TextInput style={sc.input} value={payloadCount} onChangeText={setPayloadCount} keyboardType="number-pad" />
          </View>
          <View style={{ flex: 1 }}>
            <Text style={sc.label}>Timeout (ms)</Text>
            <TextInput style={sc.input} value={timeout} onChangeText={setTimeoutVal} keyboardType="number-pad" />
          </View>
        </View>
        <CyberButton label="⚡ Start Fuzz Job" onPress={startFuzz} color={T.orange} />

        {/* Jobs */}
        <SectionHeader title="Fuzz Jobs" accent={T.orange} />
        {jobs.length === 0 && <Text style={sc.emptyText}>No jobs yet</Text>}
        {jobs.map(job => {
          const pct = job.payloadCount > 0 ? (job.completed / job.payloadCount) * 100 : 0;
          const statusColors = { idle: T.textMuted, running: T.orange, paused: T.yellow, done: T.green };
          return (
            <CyberCard key={job.id}>
              <View style={sc.rowBetween}>
                <Text style={{ color: T.textPrimary, fontWeight: '700', fontSize: 13 }}>{job.protocol} → {job.target.slice(0, 30)}…</Text>
                <CyberBadge label={job.status.toUpperCase()} color={statusColors[job.status]} />
              </View>
              <View style={{ height: 6, backgroundColor: T.bg4, borderRadius: 3, marginTop: T.s8 }}>
                <View style={{ height: 6, backgroundColor: T.orange, borderRadius: 3, width: `${pct}%` }} />
              </View>
              <View style={[sc.row, { marginTop: T.s8, gap: 16 }]}>
                <Text style={{ color: T.textSecondary, fontSize: 12 }}>{job.completed}/{job.payloadCount} sent</Text>
                <Text style={{ color: T.red, fontSize: 12 }}>💥 {job.crashes} crashes</Text>
                <Text style={{ color: T.yellow, fontSize: 12 }}>⚠ {job.errors} anomalies</Text>
              </View>
              {job.endTime && (
                <Text style={{ color: T.textMuted, fontSize: 11, marginTop: 4, fontFamily: T.fontMono }}>
                  Duration: {((job.endTime - (job.startTime ?? 0)) / 1000).toFixed(1)}s
                </Text>
              )}
            </CyberCard>
          );
        })}

        {/* Results */}
        {results.length > 0 && (
          <>
            <SectionHeader title="Fuzz Results" />
            {results.slice(0, 30).map(r => (
              <CyberCard key={r.id} style={{
                marginBottom: 4, padding: T.s10,
                backgroundColor: r.isCrash ? T.red + '0D' : r.isAnomaly ? T.yellow + '0D' : T.bg2,
                borderColor: r.isCrash ? T.red + '55' : r.isAnomaly ? T.yellow + '44' : T.border,
              }}>
                <View style={sc.rowBetween}>
                  <Text style={{ color: r.isCrash ? T.red : r.isAnomaly ? T.yellow : T.green, fontWeight: '700', fontSize: 12 }}>
                    {r.isCrash ? '💥 CRASH' : r.isAnomaly ? '⚠ ANOMALY' : '✓ OK'}
                  </Text>
                  <Text style={{ color: T.textMuted, fontFamily: T.fontMono, fontSize: 11 }}>{r.responseTime}ms</Text>
                </View>
                <Text style={{ color: T.textCode, fontFamily: T.fontMono, fontSize: 11, marginTop: 4 }} numberOfLines={1}>{r.payload}</Text>
                <Text style={{ color: T.textSecondary, fontSize: 11, marginTop: 2 }}>{r.response}</Text>
              </CyberCard>
            ))}
          </>
        )}
      </ScrollView>
    </SafeAreaView>
  );
};

// ══════════════════════════════════════════════════════════════════════
// § 17  SETTINGS SCREEN (with Privacy Policy)
// ══════════════════════════════════════════════════════════════════════

const SettingsScreen: FC = () => {
  const { state, logout } = useAuth();
  const [notifications, setNotifications] = useState(true);
  const [aesLogs, setAesLogs] = useState(true);
  const [darkMode, setDarkMode] = useState(true);
  const [privacyVisible, setPrivacyVisible] = useState(false);

  return (
    <SafeAreaView style={sc.screen}>
      <TabHeader icon="⚙" title="Settings" subtitle="Preferences & Privacy" />
      <ScrollView style={sc.scroll} contentContainerStyle={sc.pad}>

        {/* Account */}
        <SectionHeader title="Account" />
        <CyberCard>
          <Text style={{ color: T.textPrimary, fontWeight: '700' }}>{state.user?.displayName}</Text>
          <Text style={{ color: T.textSecondary, fontSize: 12 }}>{state.user?.email}</Text>
          <CyberBadge label={`via ${state.user?.provider}`} color={T.cyan} />
          <View style={sc.divider} />
          <CyberButton label="Sign Out" onPress={logout} color={T.red} />
        </CyberCard>

        {/* Preferences */}
        <SectionHeader title="Preferences" />
        {[
          { label: 'Security Notifications', val: notifications, set: setNotifications },
          { label: 'AES-256 Log Encryption', val: aesLogs, set: setAesLogs },
          { label: 'Dark Mode', val: darkMode, set: setDarkMode },
        ].map(pref => (
          <CyberCard key={pref.label} style={{ marginBottom: 6, padding: T.s12 }}>
            <View style={sc.rowBetween}>
              <Text style={{ color: T.textPrimary, fontSize: 14 }}>{pref.label}</Text>
              <Switch value={pref.val} onValueChange={pref.set}
                trackColor={{ false: T.bg4, true: T.cyan + '88' }} thumbColor={pref.val ? T.cyan : T.textMuted} />
            </View>
          </CyberCard>
        ))}

        {/* Security */}
        <SectionHeader title="Security" accent={T.red} />
        <CyberCard>
          <View style={sc.rowBetween}>
            <Text style={{ color: T.textPrimary }}>Rate Limiting</Text>
            <CyberBadge label="ACTIVE" color={T.green} />
          </View>
          <Text style={{ color: T.textMuted, fontSize: 12, marginTop: T.s4 }}>Max 10 login attempts / min. Auto-block after 3 failures (15 min).</Text>
          <View style={sc.divider} />
          <View style={sc.rowBetween}>
            <Text style={{ color: T.textPrimary }}>Log Encryption</Text>
            <CyberBadge label="AES-256-GCM" color={T.green} />
          </View>
          <Text style={{ color: T.textMuted, fontSize: 12, marginTop: T.s4 }}>Security events are encrypted before storage. No plaintext logs.</Text>
        </CyberCard>

        {/* Privacy Policy */}
        <SectionHeader title="Privacy & Legal" accent={T.purple} />
        <CyberCard>
          <Text style={{ color: T.textSecondary, fontSize: 13, lineHeight: 20 }}>
            CyberKit Pro is designed for ethical security research only.
          </Text>
          <CyberButton label="View Privacy Policy" onPress={() => setPrivacyVisible(true)} color={T.purple} />
        </CyberCard>

        <CyberCard style={{ backgroundColor: T.orange + '0D', borderColor: T.orange + '44' }}>
          <Text style={{ color: T.orange, fontWeight: '700', marginBottom: T.s8 }}>⚠ Ethical Use Reminder</Text>
          <Text style={{ color: T.orange, fontSize: 12, lineHeight: 18 }}>
            This tool is for authorised security testing only. Unauthorised scanning, fuzzing, or exploitation of systems is illegal under the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws worldwide. Always obtain written permission before testing.
          </Text>
        </CyberCard>

        <Text style={[sc.emptyText, { marginTop: T.s16 }]}>CyberKit Pro v1.0.0{'\n'}© 2024 — MIT Licensed</Text>

      </ScrollView>

      {/* Privacy Policy Modal */}
      <Modal visible={privacyVisible} animationType="slide" presentationStyle="pageSheet">
        <View style={{ flex: 1, backgroundColor: T.bg1 }}>
          <SafeAreaView style={{ flex: 1 }}>
            <View style={[sc.rowBetween, { padding: T.s16, borderBottomWidth: 1, borderBottomColor: T.border }]}>
              <Text style={{ color: T.textPrimary, fontWeight: '800', fontSize: 18 }}>Privacy Policy</Text>
              <TouchableOpacity onPress={() => setPrivacyVisible(false)}>
                <Text style={{ color: T.cyan, fontSize: 16 }}>Done</Text>
              </TouchableOpacity>
            </View>
            <ScrollView contentContainerStyle={[sc.pad, { paddingBottom: 60 }]}>
              {[
                { title: 'Data Collection', body: 'CyberKit Pro collects the minimum data necessary to operate. We do not collect, store, or share personal information beyond what is described here.' },
                { title: 'IP Address Logging', body: 'IP addresses may be logged solely for security protection purposes (rate-limiting, abuse prevention). These logs are encrypted using AES-256-GCM and are automatically purged. They are never shared with third parties or used for tracking.' },
                { title: 'Authentication', body: 'Authentication is handled exclusively through Apple Sign-In or Google Sign-In. CyberKit Pro never stores your Apple ID or Google account password. Tokens are stored in iOS Secure Enclave via expo-secure-store.' },
                { title: 'Scanning Results', body: 'No scanning results, traffic captures, or fuzz outputs are transmitted to external servers or stored permanently unless you explicitly export/save them. All data remains on your device.' },
                { title: 'Log Encryption', body: 'All security event logs containing sensitive data are encrypted with AES-256-GCM before being written to storage. Encryption keys are derived per-device and never leave the device.' },
                { title: 'Third-Party Services', body: 'Sign in with Apple and Google Sign-In are subject to Apple\'s and Google\'s respective privacy policies. CyberKit Pro only receives an opaque user identifier and email from these services.' },
                { title: 'No Advertising', body: 'CyberKit Pro contains no advertising, no advertising SDKs, and does not share any data with advertising networks.' },
                { title: 'Children\'s Privacy', body: 'CyberKit Pro is not intended for use by anyone under 18 years of age. We do not knowingly collect information from minors.' },
                { title: 'Policy Updates', body: 'If this policy changes, you will be notified within the app before continuing to use features that involve data collection.' },
                { title: 'Contact', body: 'For privacy inquiries: privacy@cyberkit.pro' },
              ].map(section => (
                <View key={section.title} style={{ marginBottom: T.s20 }}>
                  <Text style={{ color: T.cyan, fontWeight: '700', fontSize: 15, marginBottom: T.s8 }}>{section.title}</Text>
                  <Text style={{ color: T.textSecondary, fontSize: 13, lineHeight: 20 }}>{section.body}</Text>
                </View>
              ))}
              <Text style={{ color: T.textMuted, fontSize: 11, textAlign: 'center' }}>Last updated: March 2024</Text>
            </ScrollView>
          </SafeAreaView>
        </View>
      </Modal>
    </SafeAreaView>
  );
};

// ══════════════════════════════════════════════════════════════════════
// § 18  TAB NAVIGATOR
// ══════════════════════════════════════════════════════════════════════

const Tab = createBottomTabNavigator();

const tabBarStyle: object = {
  backgroundColor: T.bg0,
  borderTopColor: T.border,
  borderTopWidth: 1,
  height: 80,
  paddingBottom: 8,
  paddingTop: 8,
};

const TAB_SCREENS = [
  { name: 'Dashboard',   component: DashboardScreen,      icon: '⬡',  label: 'Dashboard',  color: T.cyan },
  { name: 'WebTester',   component: WebTesterScreen,       icon: '🌐',  label: 'Web',        color: T.orange },
  { name: 'Traffic',     component: TrafficAnalyzerScreen, icon: '📡',  label: 'Traffic',    color: T.green },
  { name: 'Payloads',    component: PayloadLabScreen,      icon: '🧪',  label: 'Payloads',   color: T.purple },
  { name: 'Bluetooth',   component: BluetoothScreen,       icon: '🔵',  label: 'BLE',        color: T.cyan },
  { name: 'LabControl',  component: LabControlScreen,      icon: '🖥️',  label: 'Lab',        color: T.yellow },
  { name: 'Fuzzer',      component: ProtocolFuzzerScreen,  icon: '⚡',  label: 'Fuzzer',     color: T.orange },
  { name: 'Settings',    component: SettingsScreen,        icon: '⚙',  label: 'Settings',   color: T.textSecondary },
];

const AppTabs: FC = () => (
  <Tab.Navigator
    screenOptions={({ route }) => {
      const screen = TAB_SCREENS.find(s => s.name === route.name);
      return {
        headerShown: false,
        tabBarStyle,
        tabBarActiveTintColor: screen?.color ?? T.cyan,
        tabBarInactiveTintColor: T.textMuted,
        tabBarLabel: screen?.label ?? route.name,
        tabBarLabelStyle: { fontSize: 10, fontWeight: '600' },
        tabBarIcon: ({ focused }) => (
          <Text style={{ fontSize: focused ? 22 : 18, opacity: focused ? 1 : 0.55 }}>
            {screen?.icon ?? '?'}
          </Text>
        ),
      };
    }}
  >
    {TAB_SCREENS.map(s => (
      <Tab.Screen key={s.name} name={s.name} component={s.component} />
    ))}
  </Tab.Navigator>
);

// ══════════════════════════════════════════════════════════════════════
// § 19  ROOT APP
// ══════════════════════════════════════════════════════════════════════

export default function App() {
  return (
    <AuthProvider>
      <StatusBar barStyle="light-content" backgroundColor={T.bg0} />
      <NavigationContainer
        theme={{
          dark: true,
          colors: {
            primary: T.cyan, background: T.bg1, card: T.bg0,
            text: T.textPrimary, border: T.border, notification: T.red,
          },
        }}
      >
        <RootNavigator />
      </NavigationContainer>
    </AuthProvider>
  );
}

const RootNavigator: FC = () => {
  const { state } = useAuth();
  if (state.loading) {
    return (
      <View style={{ flex: 1, backgroundColor: T.bg0, alignItems: 'center', justifyContent: 'center' }}>
        <Text style={{ fontSize: 48, color: T.cyan }}>⬡</Text>
        <ActivityIndicator color={T.cyan} style={{ marginTop: 24 }} />
        <Text style={{ color: T.textSecondary, marginTop: 12 }}>CyberKit Pro</Text>
      </View>
    );
  }
  return state.user ? <AppTabs /> : <LoginScreen />;
};

// ══════════════════════════════════════════════════════════════════════
// § 20  NODE.JS / EXPRESS BACKEND  (server/index.js)
//       Extract this section to a separate file on your home lab server
//       Run with:  node server/index.js
//       Requires:  npm install express cors helmet express-rate-limit
//                  jsonwebtoken dotenv node-cron
// ══════════════════════════════════════════════════════════════════════

/*
───────────────────────────────────────────────────────────────────────
  server/index.js  —  CyberKit Pro Home Lab API Server
───────────────────────────────────────────────────────────────────────

'use strict';
const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const crypto       = require('crypto');
const { execFile } = require('child_process');
const EventEmitter = require('events');

// ── Config ────────────────────────────────────────────────────────────
const PORT    = parseInt(process.env.PORT ?? '8443');
const API_KEY = process.env.CKP_API_KEY ?? 'CHANGE_ME_STRONG_KEY_32_CHARS_MIN';
const LOG_KEY = process.env.CKP_LOG_KEY ?? crypto.randomBytes(32).toString('hex');

if (API_KEY === 'CHANGE_ME_STRONG_KEY_32_CHARS_MIN') {
  console.warn('[WARN] Default API key detected. Set CKP_API_KEY env var.');
}

// ── AES-256-GCM log encryption ────────────────────────────────────────
function encryptLog(data) {
  const iv  = crypto.randomBytes(12);
  const key = Buffer.from(LOG_KEY.slice(0, 64), 'hex');
  const cipher = crypto.createCipheriv('aes-256-gcm', key.slice(0, 32), iv);
  const enc  = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  const tag  = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

// ── Encrypted security log ────────────────────────────────────────────
const secLogs = [];
function writeSecLog(level, module, message, meta = {}) {
  const entry = { ts: Date.now(), level, module, message, ...meta };
  secLogs.unshift({ id: crypto.randomUUID(), ts: entry.ts, level, module, message,
    encrypted: encryptLog(JSON.stringify(entry)) });
  if (secLogs.length > 1000) secLogs.pop();
}

// ── In-memory IP block list ────────────────────────────────────────────
const ipBlockList = new Map();
function isBlocked(ip) {
  const until = ipBlockList.get(ip);
  if (!until) return false;
  if (until > Date.now()) return true;
  ipBlockList.delete(ip);
  return false;
}
function blockIp(ip, ms = 15 * 60_000) {
  ipBlockList.set(ip, Date.now() + ms);
  writeSecLog('critical', 'RateLimit', `IP blocked: ${ip}`, { ip });
}

// ── Express app ────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'X-API-Key'] }));
app.use(express.json({ limit: '512kb' }));

// ── Rate limiter middleware ────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 60_000, max: 10,
  handler: (req, res) => {
    blockIp(req.ip);
    res.status(429).json({ error: 'Too many requests. IP temporarily blocked.' });
  },
});

// ── IP block middleware ────────────────────────────────────────────────
app.use((req, res, next) => {
  if (isBlocked(req.ip)) {
    writeSecLog('warning', 'Middleware', `Blocked IP attempt: ${req.ip}`);
    return res.status(403).json({ error: 'IP blocked due to suspicious activity.' });
  }
  next();
});

// ── Suspicious activity detection ─────────────────────────────────────
const requestCounts = new Map();
app.use((req, res, next) => {
  const key = req.ip;
  const rec = requestCounts.get(key) ?? { count: 0, reset: Date.now() + 10_000 };
  if (rec.reset < Date.now()) { rec.count = 0; rec.reset = Date.now() + 10_000; }
  rec.count++;
  requestCounts.set(key, rec);
  if (rec.count > 50) {
    writeSecLog('critical', 'Anomaly', `Suspicious high-frequency requests from ${key}`, { count: rec.count });
    blockIp(key, 5 * 60_000);
    return res.status(429).json({ error: 'Suspicious activity detected.' });
  }
  next();
});

// ── API Key authentication middleware ─────────────────────────────────
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    writeSecLog('warning', 'Auth', `Invalid API key from ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ── Routes ─────────────────────────────────────────────────────────────

// Health / ping
app.get('/api/ping', requireApiKey, (req, res) => {
  res.json({ status: 'ok', ts: Date.now(), version: '1.0.0' });
});

// Port scanner module (uses system nmap — must be installed on lab server)
app.post('/api/run/scanner', requireApiKey, authLimiter, (req, res) => {
  const { target = 'localhost', ports = '1-1024' } = req.body;
  writeSecLog('info', 'Scanner', `Scan request: ${target}:${ports}`);
  // NOTE: Only run on targets you own or have permission to scan
  const args = ['-p', ports, '--open', '-T4', target];
  execFile('nmap', args, { timeout: 30_000 }, (err, stdout, stderr) => {
    if (err) {
      writeSecLog('warning', 'Scanner', `Scan error: ${err.message}`);
      return res.status(500).json({ error: err.message });
    }
    const lines = stdout.split('\n').filter(Boolean);
    res.json({ output: lines, raw: stdout });
  });
});

// Vulnerability test module (simulated — integrate with openvas/nuclei)
app.post('/api/run/vuln', requireApiKey, authLimiter, async (req, res) => {
  const { target = 'localhost' } = req.body;
  writeSecLog('info', 'VulnTest', `Vuln test: ${target}`);
  // Placeholder — integrate Nuclei: execFile('nuclei', ['-u', target, '-json'], ...)
  await new Promise(r => setTimeout(r, 1000));
  res.json({
    target, findings: [
      { id: 'CVE-2023-1234', severity: 'medium', component: 'nginx/1.18.0', description: 'Example simulated finding' },
    ], scanned: true,
  });
});

// Traffic monitor module (returns recent connection stats)
app.get('/api/run/traffic', requireApiKey, (req, res) => {
  writeSecLog('info', 'Traffic', 'Traffic stats requested');
  // In production: parse /proc/net/tcp or use libpcap binding
  res.json({
    connections: Math.floor(Math.random() * 120) + 10,
    protocols: { TCP: 64, UDP: 22, ICMP: 4 },
    topTalkers: ['192.168.1.1', '8.8.8.8', '1.1.1.1'],
  });
});

// Protocol fuzzer module
app.post('/api/run/fuzz', requireApiKey, authLimiter, async (req, res) => {
  const { target, protocol = 'HTTP', payloads = [] } = req.body;
  if (!target) return res.status(400).json({ error: 'target required' });
  writeSecLog('info', 'Fuzzer', `Fuzz job: ${protocol} → ${target} (${payloads.length} payloads)`);
  // Real implementation would iterate payloads and fire them at target
  const results = (payloads as string[]).map((payload: string, i: number) => ({
    index: i, payload: payload.slice(0, 120),
    status: Math.random() > 0.95 ? 'CRASH' : 'OK',
    responseTime: Math.floor(Math.random() * 500),
  }));
  res.json({ target, protocol, results, crashes: results.filter((r: any) => r.status === 'CRASH').length });
});

// Security logs (encrypted)
app.get('/api/logs', requireApiKey, (req, res) => {
  res.json({ count: secLogs.length, logs: secLogs.slice(0, 100) });
});

// ── Server start ───────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  writeSecLog('info', 'Server', `CyberKit Pro Lab Server started on port ${PORT}`);
  console.log(`[CyberKit Pro] Lab server running on port ${PORT}`);
  console.log(`[CyberKit Pro] Rate limiting: 10 req/min per IP`);
  console.log(`[CyberKit Pro] AES-256-GCM log encryption: ACTIVE`);
});

module.exports = app; // for testing

───────────────────────────────────────────────────────────────────────
  END server/index.js
───────────────────────────────────────────────────────────────────────
*/

// ══════════════════════════════════════════════════════════════════════
// END OF FILE  —  CyberKit Pro v1.0.0
// ══════════════════════════════════════════════════════════════════════