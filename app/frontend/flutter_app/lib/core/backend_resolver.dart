import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

const String _definedHostLanIp = String.fromEnvironment('HOST_LAN_IP');

/// Picks a working API base URL by probing /health.
///
/// Notes:
/// - Android physical device local dev: prefer `127.0.0.1` (works with `adb reverse`).
/// - Android emulator: use `10.0.2.2` to reach the host.
/// - Optional LAN fallback: `HOST_LAN_IP` can be injected at build-time.
class BackendResolver {
  static const _timeout = Duration(seconds: 2);

  static Future<String?> resolve({
    String? preferred,
    List<String>? extraCandidates,
  }) async {
    final candidates = <String>[
      if (preferred != null && preferred.trim().isNotEmpty) preferred.trim(),
      ...?extraCandidates,
      ..._defaultCandidates(),
    ];

    final seen = <String>{};
    for (final base in candidates) {
      final normalized = _normalizeBase(base);
      if (normalized == null) continue;
      if (!seen.add(normalized)) continue;
      final ok = await _probe(normalized);
      if (ok) return normalized;
    }
    return null;
  }

  static List<String> _defaultCandidates() {
    if (kIsWeb) return const ['http://localhost:4000'];

    if (defaultTargetPlatform == TargetPlatform.android) {
      final lan = _definedHostLanIp.trim();
      return [
        'http://127.0.0.1:4000',
        if (lan.isNotEmpty) 'http://$lan:4000',
        'http://10.0.2.2:4000',
      ];
    }

    return const ['http://127.0.0.1:4000'];
  }

  static String? _normalizeBase(String base) {
    var v = base.trim();
    if (v.isEmpty) return null;
    if (v.endsWith('/')) v = v.substring(0, v.length - 1);
    return v;
  }

  static Future<bool> _probe(String baseUrl) async {
    try {
      final r = await http.get(Uri.parse('$baseUrl/health')).timeout(_timeout);
      return r.statusCode >= 200 && r.statusCode < 300;
    } catch (_) {
      return false;
    }
  }
}