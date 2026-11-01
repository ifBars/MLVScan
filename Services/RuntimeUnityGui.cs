using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

// Resolve the host's Unity API at runtime: Mono uses managed Unity classes while IL2CPP uses
// generated proxy classes with different base types and delegate representations. No game
// assemblies are bundled or loaded by this bridge. Only fixed Unity UI APIs are resolved.
namespace MLVScan.Services.RuntimeGui
{
    internal static class Api
    {
        private static readonly Dictionary<string, Type> Types = new();
        private static readonly Dictionary<string, MethodInfo> Methods = new();
        internal static Type Type(string name)
        {
            if (Types.TryGetValue(name, out var type)) return type;
            type = AppDomain.CurrentDomain.GetAssemblies()
                .Where(a => a.GetName().Name.StartsWith("UnityEngine", StringComparison.Ordinal))
                .Select(a => a.GetType("UnityEngine." + name, false)).FirstOrDefault(t => t != null);
            if (type == null)
            {
                foreach (var module in new[] { "UnityEngine.CoreModule", "UnityEngine.IMGUIModule", "UnityEngine.TextRenderingModule", "UnityEngine" })
                {
                    try { type = Assembly.Load(module).GetType("UnityEngine." + name, false); }
                    catch (System.IO.FileNotFoundException) { }
                    if (type != null) break;
                }
            }
            if (type == null) throw new TypeLoadException("Unity UI type unavailable: " + name);
            return Types[name] = type;
        }
        internal static object Raw(object value) => value switch
        {
            Handle h => h.Value,
            Color c => Activator.CreateInstance(Type("Color"), c.r, c.g, c.b, c.a),
            Rect r => Activator.CreateInstance(Type("Rect"), r.x, r.y, r.width, r.height),
            Vector3 v => Activator.CreateInstance(Type("Vector3"), v.x, v.y, v.z),
            Enum e => Enum.ToObject(Type(e.GetType().Name), Convert.ToInt32(e)),
            _ => value
        };
        internal static object Get(object target, string name)
        {
            var type = target as Type ?? target.GetType();
            return type.GetProperty(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                .GetValue(target is Type ? null : target);
        }
        internal static void Set(object target, string name, object value)
        {
            var type = target as Type ?? target.GetType();
            type.GetProperty(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                .SetValue(target is Type ? null : target, Raw(value));
        }
        internal static object Call(object target, string name, params object[] args)
        {
            var type = target as Type ?? target.GetType();
            var values = args.Select(Raw).ToArray();
            var key = type.FullName + "." + name + ":" + string.Join(",", values.Select(v => v?.GetType().FullName ?? "null"));
            if (!Methods.TryGetValue(key, out var method))
            {
                method = type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance)
                    .FirstOrDefault(m => m.Name == name && !m.ContainsGenericParameters &&
                        m.GetParameters().Length == values.Length && m.GetParameters().Select((p, i) =>
                            values[i] == null ? !p.ParameterType.IsValueType : p.ParameterType.IsInstanceOfType(values[i])).All(x => x))
                    ?? throw new MissingMethodException(type.FullName, name);
                Methods[key] = method;
            }
            return method.Invoke(target is Type ? null : target, values);
        }
    }
    internal class Handle
    {
        internal object Value { get; }
        internal Handle(object value) { Value = value; }
    }
    internal struct Color
    {
        internal float r, g, b, a;
        internal Color(float r, float g, float b, float a = 1) { this.r=r; this.g=g; this.b=b; this.a=a; }
        internal static Color white => new(1,1,1);
        internal static Color black => new(0,0,0);
        internal static Color Lerp(Color x, Color y, float t) => new(x.r+(y.r-x.r)*t,x.g+(y.g-x.g)*t,x.b+(y.b-x.b)*t,x.a+(y.a-x.a)*t);
    }
    internal struct Rect
    {
        internal float x,y,width,height;
        internal Rect(float x,float y,float width,float height) { this.x=x;this.y=y;this.width=width;this.height=height; }
    }
    internal struct Vector3
    {
        internal float x,y,z;
        internal Vector3(float x,float y,float z) { this.x=x;this.y=y;this.z=z; }
    }
    internal enum CursorLockMode { None, Locked, Confined }
    internal enum FontStyle { Normal, Bold, Italic, BoldAndItalic }
    internal enum TextAnchor { UpperLeft, UpperCenter, UpperRight, MiddleLeft, MiddleCenter }
    internal enum TextureFormat { RGBA32 = 4 }
    internal enum HideFlags { HideAndDontSave = 61 }
    internal static class Screen
    {
        internal static int width => (int)Api.Get(Api.Type("Screen"), "width");
        internal static int height => (int)Api.Get(Api.Type("Screen"), "height");
    }
    internal static class Cursor
    {
        internal static bool visible { get => (bool)Api.Get(Api.Type("Cursor"), "visible"); set => Api.Set(Api.Type("Cursor"), "visible", value); }
        internal static CursorLockMode lockState { get => (CursorLockMode)Convert.ToInt32(Api.Get(Api.Type("Cursor"), "lockState")); set => Api.Set(Api.Type("Cursor"), "lockState", value); }
    }
    internal sealed class Matrix4x4 : Handle
    {
        internal Matrix4x4(object value) : base(value) { }
        internal static Matrix4x4 identity => new(Api.Get(Api.Type("Matrix4x4"), "identity"));
        internal static Matrix4x4 Scale(Vector3 value) => new(Api.Call(Api.Type("Matrix4x4"), "Scale", value));
    }
    internal sealed class Texture2D : Handle
    {
        internal Texture2D(int width,int height,TextureFormat format,bool mipmap) : base(Activator.CreateInstance(Api.Type("Texture2D"),width,height,Api.Raw(format),mipmap)) { }
        private Texture2D(object value) : base(value) { }
        internal static Texture2D whiteTexture => new(Api.Get(Api.Type("Texture2D"), "whiteTexture"));
        internal HideFlags hideFlags { set => Api.Set(Value,"hideFlags",value); }
        internal void SetPixel(int x,int y,Color color) => Api.Call(Value,"SetPixel",x,y,color);
        internal void Apply() => Api.Call(Value,"Apply");
        internal void Destroy() => Api.Call(Api.Type("Object"),"Destroy",this);
    }
    internal sealed class StyleState : Handle
    {
        internal StyleState(object value) : base(value) { }
        internal Texture2D background { set => Api.Set(Value,"background",value); }
        internal Color textColor { set => Api.Set(Value,"textColor",value); }
    }
    internal sealed class Border : Handle
    {
        internal Border(object value) : base(value) { }
        internal int left { set => Api.Set(Value,"left",value); }
        internal int right { set => Api.Set(Value,"right",value); }
        internal int top { set => Api.Set(Value,"top",value); }
        internal int bottom { set => Api.Set(Value,"bottom",value); }
    }
    internal sealed class GUIStyle : Handle
    {
        internal GUIStyle() : base(Activator.CreateInstance(Api.Type("GUIStyle"))) { }
        internal StyleState normal => new(Api.Get(Value,"normal"));
        internal StyleState hover => new(Api.Get(Value,"hover"));
        internal StyleState focused => new(Api.Get(Value,"focused"));
        internal StyleState active => new(Api.Get(Value,"active"));
        internal Border border => new(Api.Get(Value,"border"));
        internal int fontSize { set => Api.Set(Value,"fontSize",value); }
        internal FontStyle fontStyle { set => Api.Set(Value,"fontStyle",value); }
        internal bool wordWrap { set => Api.Set(Value,"wordWrap",value); }
        internal bool richText { set => Api.Set(Value,"richText",value); }
        internal TextAnchor alignment { set => Api.Set(Value,"alignment",value); }
    }
    internal static class GUI
    {
        private static Type UnityType => Api.Type("GUI");
        private static Action<int> _callback;
        private static object _windowFunction;
        internal static Matrix4x4 matrix { get => new(Api.Get(UnityType,"matrix")); set => Api.Set(UnityType,"matrix",value); }
        // Preserve native Color values verbatim when restoring GUI state.
        internal static object color { get => Api.Get(UnityType,"color"); set => Api.Set(UnityType,"color",value); }
        internal static object backgroundColor { get => Api.Get(UnityType,"backgroundColor"); set => Api.Set(UnityType,"backgroundColor",value); }
        internal static object contentColor { get => Api.Get(UnityType,"contentColor"); set => Api.Set(UnityType,"contentColor",value); }
        internal static int depth { get => (int)Api.Get(UnityType,"depth"); set => Api.Set(UnityType,"depth",value); }
        internal static void Box(Rect rect,string text,GUIStyle style) => Api.Call(UnityType,"Box",rect,text,style);
        internal static void Label(Rect rect,string text,GUIStyle style) => Api.Call(UnityType,"Label",rect,text,style);
        internal static bool Button(Rect rect,string text,GUIStyle style) => (bool)Api.Call(UnityType,"Button",rect,text,style);
        internal static void SetNextControlName(string name) => Api.Call(UnityType,"SetNextControlName",name);
        internal static void ModalWindow(int id,Rect rect,Action<int> callback,string text,GUIStyle style)
        {
            if (_callback != callback)
            {
                var type = UnityType.GetNestedType("WindowFunction");
                _windowFunction = typeof(Delegate).IsAssignableFrom(type)
                    ? Delegate.CreateDelegate(type, callback.Target, callback.Method)
                    : type.GetMethods(BindingFlags.Public | BindingFlags.Static).First(m => m.Name == "op_Implicit" &&
                        m.GetParameters().Length == 1 && m.GetParameters()[0].ParameterType == typeof(Action<int>)).Invoke(null,new object[]{callback});
                _callback = callback;
            }
            Api.Call(UnityType,"ModalWindow",id,rect,_windowFunction,text,style);
        }
    }
}
