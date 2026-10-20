import 'package:flutter/material.dart';
import 'api.dart';

void main() => runApp(const AtlasNotes());

class AtlasNotes extends StatelessWidget {
  const AtlasNotes({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Atlas Notes 合成デモ',
    theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
    home: const NotesPage(),
  );
}

class NotesPage extends StatefulWidget {
  const NotesPage({super.key});
  @override
  State<NotesPage> createState() => _NotesPageState();
}

class _NotesPageState extends State<NotesPage> {
  final NotesGateway gateway = DemoGateway();
  final title = TextEditingController();
  final body = TextEditingController();
  final inquiry = TextEditingController();
  List<Map<String, dynamic>> items = [];
  String status = '通信しないメモリ内デモ';
  bool busy = false;
  @override
  void initState() { super.initState(); refresh(); }
  Future<void> refresh() async {
    final result = await gateway.notes();
    if (mounted) setState(() => items = result);
  }
  Future<void> perform(Future<void> Function() action) async {
    if (busy) return;
    setState(() => busy = true);
    try { await action(); } catch (_) {
      if (mounted) setState(() => status = '入力と権限を確認してください');
    } finally { if (mounted) setState(() => busy = false); }
  }
  @override
  void dispose() {
    gateway.close(); title.dispose(); body.dispose(); inquiry.dispose(); super.dispose();
  }
  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Atlas Notes')),
    body: Center(child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 700),
      child: ListView(padding: const EdgeInsets.all(20), children: [
        Text(status, semanticsLabel: '処理結果: $status'),
        const SizedBox(height: 20),
        TextField(controller: title, maxLength: 120, decoration: const InputDecoration(labelText: 'タイトル')),
        TextField(controller: body, maxLength: 4000, maxLines: 3, decoration: const InputDecoration(labelText: '本文')),
        FilledButton(onPressed: busy ? null : () => perform(() async {
          if (title.text.trim().isEmpty) throw const FormatException('Title required');
          await gateway.add(title.text, body.text); await refresh();
        }), child: const Text('ノートを追加')),
        for (final item in items) Card(child: ListTile(
          title: Text(item['title'] as String), subtitle: Text(item['body'] as String))),
        const Divider(),
        TextField(controller: inquiry, maxLength: 4000, maxLines: 4,
          decoration: const InputDecoration(labelText: '問い合わせ内容')),
        FilledButton(onPressed: busy ? null : () => perform(() async {
          if (inquiry.text.trim().isEmpty) throw const FormatException('Body required');
          final id = await gateway.contact(inquiry.text);
          if (mounted) setState(() => status = '受け付けました: $id');
        }), child: const Text('問い合わせを受付')),
        const Text('受付通知は固定文面です。問い合わせ本文をメールへ引用しません。'),
      ]))),
  );
}
