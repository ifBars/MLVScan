using System;
using System.Collections.Generic;
using MLVScan.Services.RuntimeGui;

namespace MLVScan.Services
{
    /// <summary>Shared IMGUI presentation for all loader runtimes. No consent or network side effects.</summary>
    public sealed class SharingConsentView : IDisposable
    {
        private readonly Action<bool, bool> _decide;
        private readonly List<Texture2D> _textures = new List<Texture2D>();
        private bool _shareFiles;
        private bool _details;
        private bool _cursorCaptured;
        private bool _oldCursorVisible;
        private CursorLockMode _oldCursorLock;
        private GUIStyle _panel, _overlay, _brand, _eyebrow, _title, _body, _small, _primary, _secondary, _link, _option, _check;
        private static readonly Color Accent = new Color(0.086f, 0.792f, 0.71f);
        private static readonly Color Text = new Color(0.95f, 0.97f, 0.99f);
        private static readonly Color Muted = new Color(0.63f, 0.69f, 0.77f);
        public bool IsOpen { get; private set; } = true;

        public SharingConsentView(bool initialFileChoice, Action<bool, bool> decide)
        {
            _shareFiles = initialFileChoice;
            _decide = decide ?? throw new ArgumentNullException(nameof(decide));
        }

        public void Draw()
        {
            if (!IsOpen || Screen.width <= 0 || Screen.height <= 0) return;
            try { EnsureStyles(); }
            catch { IsOpen = false; throw; }
            if (!_cursorCaptured)
            {
                _oldCursorVisible = Cursor.visible;
                _oldCursorLock = Cursor.lockState;
                _cursorCaptured = true;
            }
            Cursor.lockState = CursorLockMode.None;
            Cursor.visible = true;
            var previousMatrix = GUI.matrix;
            var previousColor = GUI.color;
            var previousBackground = GUI.backgroundColor;
            var previousContent = GUI.contentColor;
            var previousDepth = GUI.depth;
            try
            {
                GUI.depth = -10000;
                GUI.color = Color.white;
                GUI.backgroundColor = Color.white;
                GUI.contentColor = Color.white;
                var height = _details ? 586f : 380f;
                var scale = Math.Min(1.25f, Math.Min((Screen.width - 24f) / 560f, (Screen.height - 24f) / height));
                scale = Math.Max(0.1f, scale);
                GUI.matrix = Matrix4x4.identity;
                GUI.Box(new Rect(0, 0, Screen.width, Screen.height), string.Empty, _overlay);
                GUI.color = Color.white;
                GUI.matrix = Matrix4x4.Scale(new Vector3(scale, scale, 1));
                var bounds = new Rect((Screen.width / scale - 560f) / 2f, (Screen.height / scale - height) / 2f, 560f, height);
                GUI.ModalWindow(0x4D4C56, bounds, DrawContents, string.Empty, _panel);
            }
            catch
            {
                // Fail closed without throwing on every subsequent Unity GUI event.
                IsOpen = false;
                RestoreCursor();
                throw;
            }
            finally
            {
                GUI.matrix = previousMatrix;
                GUI.color = previousColor;
                GUI.backgroundColor = previousBackground;
                GUI.contentColor = previousContent;
                GUI.depth = previousDepth;
            }
        }

        private void DrawContents(int id)
        {
            GUI.Label(new Rect(32, 27, 170, 28), "MLVScan", _brand);
            GUI.Label(new Rect(360, 33, 168, 20), "YOUR PRIVACY. YOUR CHOICE.", _eyebrow);
            GUI.Label(new Rect(32, 82, 496, 38), "Help improve MLVScan", _title);
            GUI.Label(new Rect(32, 130, 490, 50),
                "Share scan diagnostics to improve detection. Files stay local unless you choose to share them.", _body);

            GUI.SetNextControlName("share-files");
            if (GUI.Button(new Rect(32, 199, 496, 62), string.Empty, _option)) _shareFiles = !_shareFiles;
            GUI.Box(new Rect(49, 218, 22, 22), _shareFiles ? "✓" : string.Empty, _check);
            GUI.Label(new Rect(85, 208, 423, 24), "Also share files and reports for private review", _body);
            GUI.Label(new Rect(85, 233, 423, 18), "Optional · flagged or incomplete scan results", _small);

            if (GUI.Button(new Rect(32, 273, 130, 25), _details ? "Less detail  −" : "Learn more  +", _link))
                _details = !_details;
            GUI.Label(new Rect(280, 278, 248, 18), "Change your choice in settings anytime.", _small);

            if (_details)
            {
                GUI.Label(new Rect(32, 318, 496, 22), "WHAT YOU SHARE", _eyebrow);
                GUI.Label(new Rect(32, 348, 496, 65),
                    "PostHog receives scan outcomes, rule and behavior categories, cache status and scanner versions, plus private review references when files are shared. No filenames, paths, hashes, code or lasting user ID.", _small);
                GUI.Label(new Rect(32, 416, 496, 58),
                    "Optional files and reports are stored with Cloudflare for MLVScan reviewers. We do not publish or redistribute these submissions, including false positives.", _small);
                GUI.Label(new Rect(32, 480, 496, 34),
                    "Files may contain personal data. Providers handle the connection; location enrichment is off. Scanning stays local, open and free.", _small);
            }

            var buttonY = _details ? 532f : 326f;
            GUI.SetNextControlName("decline-sharing");
            if (GUI.Button(new Rect(32, buttonY, 238, 40), "No thanks", _secondary)) Complete(false);
            GUI.SetNextControlName("allow-sharing");
            if (GUI.Button(new Rect(290, buttonY, 238, 40), "Allow sharing", _primary)) Complete(true);
        }

        private void Complete(bool allow)
        {
            _decide(allow, _shareFiles);
            IsOpen = false;
            RestoreCursor();
        }

        private void EnsureStyles()
        {
            if (_panel != null) return;
            _panel = Surface(new Color(0.055f, 0.071f, 0.102f), 14);
            _overlay = new GUIStyle { normal = { background = Texture2D.whiteTexture } };
            // GUI.DrawTexture is stripped in some IL2CPP games; a style background uses the native GUI path.
            var overlayTexture = new Texture2D(1, 1, TextureFormat.RGBA32, false);
            overlayTexture.SetPixel(0, 0, new Color(0.015f, 0.025f, 0.04f, 0.86f));
            overlayTexture.Apply();
            _textures.Add(overlayTexture);
            _overlay.normal.background = overlayTexture;
            _brand = Label(23, Text, FontStyle.Bold);
            _eyebrow = Label(10, Accent, FontStyle.Bold);
            _title = Label(29, Text, FontStyle.Bold);
            _body = Label(16, Text);
            _small = Label(13, Muted);
            _primary = Button(Accent, new Color(0.018f, 0.10f, 0.09f));
            _secondary = Button(new Color(0.14f, 0.17f, 0.22f), Text);
            _option = Button(new Color(0.085f, 0.108f, 0.15f), Text);
            _check = Surface(new Color(0.20f, 0.27f, 0.32f), 5);
            _check.fontSize = 17;
            _check.alignment = TextAnchor.MiddleCenter;
            _check.normal.textColor = Accent;
            _link = Label(13, Accent, FontStyle.Bold);
            _link.hover.textColor = Text;
            _link.focused.textColor = Text;
        }

        private static GUIStyle Label(int size, Color color, FontStyle weight = FontStyle.Normal) =>
            new GUIStyle { fontSize = size, fontStyle = weight, wordWrap = true, richText = false,
                normal = { textColor = color } };

        private GUIStyle Button(Color background, Color foreground)
        {
            var style = Surface(background, 8);
            style.fontSize = 14;
            style.fontStyle = FontStyle.Bold;
            style.alignment = TextAnchor.MiddleCenter;
            style.normal.textColor = foreground;
            style.hover.background = Rounded(Color.Lerp(background, Color.white, 0.10f), 8);
            style.hover.textColor = foreground;
            style.focused.background = Rounded(Color.Lerp(background, Color.white, 0.10f), 8);
            style.focused.textColor = foreground;
            style.active.background = Rounded(Color.Lerp(background, Color.black, 0.12f), 8);
            style.active.textColor = foreground;
            return style;
        }

        private GUIStyle Surface(Color color, int radius)
        {
            var style = new GUIStyle { normal = { background = Rounded(color, radius) } };
            style.border.left = radius;
            style.border.right = radius;
            style.border.top = radius;
            style.border.bottom = radius;
            return style;
        }

        private Texture2D Rounded(Color color, int radius)
        {
            const int size = 32;
            var texture = new Texture2D(size, size, TextureFormat.RGBA32, false);
            texture.hideFlags = HideFlags.HideAndDontSave;
            for (var y = 0; y < size; y++)
                for (var x = 0; x < size; x++)
                {
                    var dx = Math.Max(radius - x - 0.5f, Math.Max(x + 0.5f - (size - radius), 0));
                    var dy = Math.Max(radius - y - 0.5f, Math.Max(y + 0.5f - (size - radius), 0));
                    var pixel = color;
                    pixel.a *= (float)Math.Max(0, Math.Min(1, radius - Math.Sqrt(dx * dx + dy * dy)));
                    texture.SetPixel(x, y, pixel);
                }
            texture.Apply();
            _textures.Add(texture);
            return texture;
        }

        private void RestoreCursor()
        {
            if (!_cursorCaptured) return;
            Cursor.lockState = _oldCursorLock;
            Cursor.visible = _oldCursorVisible;
            _cursorCaptured = false;
        }

        public void Dispose()
        {
            IsOpen = false;
            RestoreCursor();
            foreach (var texture in _textures) texture.Destroy();
            _textures.Clear();
        }
    }
}
