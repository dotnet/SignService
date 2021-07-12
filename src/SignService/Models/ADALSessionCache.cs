//using System.Threading;
//using Microsoft.AspNetCore.Http;
//using Microsoft.IdentityModel.Clients.ActiveDirectory;

//namespace SignService.Models
//{
//    public class ADALSessionCache : TokenCache
//    {
//        readonly ReaderWriterLockSlim sessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
//        readonly string cacheId = string.Empty;
//        readonly IHttpContextAccessor httpContext;

//        public ADALSessionCache(string userId, IHttpContextAccessor httpcontext)
//        {
//            // not object, we want the SUB
//            cacheId = userId + "_TokenCache";
//            httpContext = httpcontext;
//            AfterAccess = AfterAccessNotification;
//            BeforeAccess = BeforeAccessNotification;
//            Load();
//        }

//        public void SaveUserStateValue(string state)
//        {
//            sessionLock.EnterWriteLock();

//            httpContext.HttpContext.Session.SetString(cacheId + "_state", state);
//            sessionLock.ExitWriteLock();
//        }
//        public string ReadUserStateValue()
//        {
//            sessionLock.EnterReadLock();
//            //this.Deserialize((byte[])HttpContext.Current.Session[CacheId]);
//            var state = httpContext.HttpContext.Session.GetString(cacheId + "_state");
//            sessionLock.ExitReadLock();
//            return state;
//        }
//        public void Load()
//        {
//            sessionLock.EnterReadLock();
//            //this.Deserialize((byte[])HttpContext.Current.Session[CacheId]);
//            DeserializeAdalV3(httpContext.HttpContext.Session.Get(cacheId));
            
//            sessionLock.ExitReadLock();
//        }

//        public void Persist()
//        {
//            sessionLock.EnterWriteLock();

//            // Optimistically set HasStateChanged to false. We need to do it early to avoid losing changes made by a concurrent thread.
//            HasStateChanged = false;

//            // Reflect changes in the persistent store
//            httpContext.HttpContext.Session.Set(cacheId, SerializeAdalV3());
//            sessionLock.ExitWriteLock();
//        }

//        // Empties the persistent store.
//        public override void Clear()
//        {
//            base.Clear();
//            httpContext.HttpContext.Session.Remove(cacheId);
//        }

//        // Triggered right before ADAL needs to access the cache.
//        // Reload the cache from the persistent store in case it changed since the last access.
//        void BeforeAccessNotification(TokenCacheNotificationArgs args)
//        {
//            Load();
//        }

//        // Triggered right after ADAL accessed the cache.
//        void AfterAccessNotification(TokenCacheNotificationArgs args)
//        {
//            // if the access operation resulted in a cache update
//            if (HasStateChanged)
//            {
//                Persist();
//            }
//        }
//    }
//}
