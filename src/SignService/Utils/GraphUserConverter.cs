using System;
using System.Linq;
using System.Reflection;

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SignService.Models;

namespace SignService.Utils
{
    public class GraphUserConverterWithNulls : GraphUserConverter
    {
        protected override bool SkipNulls => false;

        protected override object CreateBlankObject() => new GraphUserUpdate();

        public override bool CanConvert(Type objectType) => objectType == typeof(GraphUserUpdate);
    }

    public class GraphUserConverter : JsonConverter
    {
        protected virtual bool SkipNulls => true;

        static string appId;

        public GraphUserConverter()
        {
            // Get the settings if needed
            if (appId == null)
            {
                var settings = JsonConvert.DefaultSettings();
                var jsonContract = settings.ContractResolver.ResolveContract(typeof(IOptionsMonitor<MicrosoftIdentityOptions>));
                var aadOptions = (IOptionsMonitor<MicrosoftIdentityOptions>)jsonContract.DefaultCreator();
                appId = aadOptions.Get(OpenIdConnectDefaults.AuthenticationScheme).ClientId.Replace("-", "");
            }
        }

        /// <summary>
        /// This method will create a Json object from the GraphUser
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="value"></param>
        /// <param name="serializer"></param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var graphUser = value;

            if (graphUser == null)
            {
                return;
            }

            var jObject = new JObject();
            var extensionProps = typeof(IGraphUserExtensions).GetProperties();
            foreach (var prop in extensionProps)
            {
                var name = JsonPropertyName(prop);
                var propNameCamelCase = $"{name.Substring(0, 1).ToLowerInvariant()}{name.Substring(1)}";
                var extPropName = $"extension_{appId}_{propNameCamelCase}";
                var val = prop.GetValue(graphUser);
                if (val == null && SkipNulls)
                {
                    continue;
                }

                var newExtProp = new JProperty(extPropName, val);

                //Create new prop
                jObject.Add(newExtProp);
            }

            var graphProps = graphUser.GetType().GetProperties();
            var extPropNames = extensionProps.Select(m => m.Name);
            foreach (var coreProp in graphProps.Where(m => !extPropNames.Contains(m.Name)))
            {
                var name = JsonPropertyName(coreProp);
                var propNameCamelCase = $"{name.Substring(0, 1).ToLowerInvariant()}{name.Substring(1)}";
                var val = coreProp.GetValue(graphUser);
                if (val == null && SkipNulls)
                {
                    continue;
                }

                var newCoreProp = new JProperty(propNameCamelCase, JToken.FromObject(val));

                jObject.Add(newCoreProp);
            }

            jObject.WriteTo(writer);
        }
        /// <summary>
        /// This method will convert the Json into the GraphUser object
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="objectType"></param>
        /// <param name="existingValue"></param>
        /// <param name="serializer"></param>
        /// <returns></returns>
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue,
            JsonSerializer serializer)
        {
            var graphUser = CreateBlankObject();
            var graphProps = graphUser.GetType().GetProperties();
            var o = JObject.Load(reader);

            //Read extension methods and write it to new graphObject
            var extensionProps = typeof(IGraphUserExtensions).GetProperties();
            foreach (var prop in extensionProps)
            {
                var name = JsonPropertyName(prop);
                var propNameCamelCase = $"{name.Substring(0, 1).ToLowerInvariant()}{name.Substring(1)}";
                var extPropName = $"extension_{appId}_{propNameCamelCase}";

                var extPropValue = o.Property(extPropName);
                if (extPropValue == null)
                {
                    continue;
                }

                var propVal = extPropValue.Value.ToString();
                var convertedVal = extPropValue.Value.ToObject(prop.PropertyType);
                var graphProp = graphProps.FirstOrDefault(m => m.Name == prop.Name);
                if (graphProp == null)
                {
                    continue;
                }

                graphProp.SetValue(graphUser, convertedVal);
            }

            //Read core properties and write it to new object
            foreach (var coreProp in graphProps.Where(m => !extensionProps.Contains(m)))
            {
                var name = JsonPropertyName(coreProp);
                var propNameCamelCase = $"{name.Substring(0, 1).ToLowerInvariant()}{name.Substring(1)}";
                var jPropVal = o.Property(propNameCamelCase);
                if (jPropVal == null)
                {
                    continue;
                }

                var convertedVal = jPropVal.Value.ToObject(coreProp.PropertyType);
                coreProp.SetValue(graphUser, convertedVal);
            }

            return graphUser;
        }

        protected virtual object CreateBlankObject() => new GraphUser();

        static string JsonPropertyName(PropertyInfo propertyInfo)
        {
            // see if there's a JsonProperty attribute on it
            var attrib = propertyInfo.GetCustomAttribute<JsonPropertyAttribute>();
            return attrib?.PropertyName ?? propertyInfo.Name;
        }

        public override bool CanConvert(Type objectType)
        {
            return (objectType == typeof(GraphUser));
        }

    }
}
