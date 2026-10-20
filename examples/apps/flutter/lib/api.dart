import 'dart:convert';
import 'dart:io';

abstract class NotesGateway {
  Future<List<Map<String, dynamic>>> notes();
  Future<void> add(String title, String body);
  Future<String> contact(String body);
  void close();
}

class DemoGateway implements NotesGateway {
  final _items = <Map<String, dynamic>>[
    {'title': '合成モバイルデモ', 'body': 'iOS / Android共通の参照UIです。'}
  ];
  @override
  Future<List<Map<String, dynamic>>> notes() async => List.unmodifiable(_items);
  @override
  Future<void> add(String title, String body) async => _items.add({'title': title, 'body': body});
  @override
  Future<String> contact(String body) async => 'synthetic-receipt';
  @override
  void close() {}
}

class HttpsGateway implements NotesGateway {
  final HttpClient _client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
  String _token;
  HttpsGateway(this._token);
  // Token stays in memory. No certificate bypass, app-bundled shared secret or HTTP fallback.
  Future<Map<String, dynamic>> _request(String path, {Map<String, Object>? body}) async {
    if (!{'/v1/notes', '/v1/inquiries'}.contains(path)) throw ArgumentError('Unknown route');
    final uri = Uri.https('api.atlas.invalid', path);
    final request = await _client.openUrl(body == null ? 'GET' : 'POST', uri)
        .timeout(const Duration(seconds: 10));
    request.followRedirects = false;
    request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $_token');
    request.headers.contentType = ContentType.json;
    if (body != null) request.write(jsonEncode(body));
    final response = await request.close().timeout(const Duration(seconds: 10));
    if (response.statusCode < 200 || response.statusCode >= 300) {
      await response.drain<void>().timeout(const Duration(seconds: 10));
      throw const HttpException('Request rejected');
    }
    final bytes = <int>[];
    await for (final chunk in response.timeout(const Duration(seconds: 10))) {
      if (bytes.length + chunk.length > 1024 * 1024) throw const HttpException('Response too large');
      bytes.addAll(chunk);
    }
    final result = jsonDecode(utf8.decode(bytes));
    if (result is! Map<String, dynamic>) throw const FormatException('Expected object');
    return result;
  }
  @override
  Future<List<Map<String, dynamic>>> notes() async {
    final value = (await _request('/v1/notes'))['items'];
    if (value is! List || value.length > 100) throw const FormatException('Invalid list');
    return value.map((item) => Map<String, dynamic>.from(item as Map)).toList();
  }
  @override
  Future<void> add(String title, String body) async {
    await _request('/v1/notes', body: {'title': title, 'body': body});
  }
  @override
  Future<String> contact(String body) async =>
      (await _request('/v1/inquiries', body: {'body': body}))['receipt_id'] as String;
  @override
  void close() { _token = ''; _client.close(force: true); }
}
