using Nebula.Authentication.Infrastructure.Attributes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Nebula.Authentication.Infrastructure
{
    /// <summary>
    /// 授权服务
    /// </summary>
    public class AuthenticationService : IAuthService
    {
        /// <summary>
        /// 授权配置
        /// </summary>
        public readonly AuthOptions _authOptions;

        /// <summary>
        /// 缓存
        /// </summary>
        public readonly IMemoryCache _memoryCache;

        /// <summary>
        /// 权限节点缓存策略
        /// </summary>
        public readonly MemoryCacheEntryOptions cacheEntryOptions = new MemoryCacheEntryOptions()
             .SetPriority(CacheItemPriority.NeverRemove);

        /// <summary>
        /// 权限节点，缓存，Key权限节点，Value是否允许访问
        /// </summary>
        public readonly IReadOnlyDictionary<string, bool> EndPoints = null;

        /// <summary>
        /// 授权服务
        /// </summary>
        /// <param name="authOptions"></param>
        /// <param name="memoryCache"></param>
        public AuthenticationService(AuthOptions authOptions, IMemoryCache memoryCache)
        {
            _authOptions = authOptions;
            _memoryCache = memoryCache;

            memoryCache.TryGetValue("Cyaim_AuthEndPoints", out EndPoints);
        }


        #region 鉴权
        /// <summary>
        /// 凭据鉴权
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public virtual async Task<bool> CheckAuthorization(HttpContext context)
        {
            string authKey = GetAuthorizationValue(context);

            //检测序列
            foreach (AccessSourceEnum item in _authOptions.AccessSources)
            {
                switch (item)
                {
                    case AccessSourceEnum.AuthCenter:
                        {

                        }
                        break;
                    case AccessSourceEnum.Cache:
                        {
                            var exr = await CheckAuthCache(context, authKey);
                            if (exr.IsPass)
                            {
                                continue;
                            }
                            return exr.IsAuth;
                        }
                    case AccessSourceEnum.Database:
                        {
                            var exr = await CheckAuthDatabase(context, authKey);
                            if (exr.IsPass)
                            {
                                Console.WriteLine();
                                Console.WriteLine($"节点  ->  {context.Request.Path}  因不在数据库权限监测范围,跳出数据库鉴权");
                                continue;
                            }
                            return exr.IsAuth;
                        }

                    case AccessSourceEnum.Default:
                        Console.WriteLine($"节点  ->  {context.Request.Path}  执行默认鉴权");
                        return CheckAuthDefault(context);
                }
            }

            return false;
        }

        /// <summary>
        /// 从缓存获取authKey的权限节点
        /// </summary>
        /// <param name="context"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public async Task<(bool IsAuth, bool IsPass)> CheckAuthCache(HttpContext context, string authKey)
        {
            var handler = _authOptions?.ExtractCacheAuthEndPoints;

            IAuthEndPointAttribute[] parm = null;
            if (handler != null)
            {
                parm = await handler?.Invoke(authKey, context, _authOptions);
            }

            bool isPass;
            if (parm == null)
            {
                isPass = true;
            }
            else
            {
                isPass = false;
            }
            return (CheckAuth(context, parm), isPass);
        }

        /// <summary>
        /// 从数据库获取authKey的权限节点
        /// </summary>
        /// <param name="context"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public async Task<(bool IsAuth, bool IsPass)> CheckAuthDatabase(HttpContext context, string authKey)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            var handler = _authOptions?.ExtractDatabaseAuthEndPoints;
            IAuthEndPointAttribute[] parm = null;
            if (handler != null)
            {
                parm = await handler?.Invoke(authKey, context, _authOptions);
            }

            stopwatch.Stop();
            Console.WriteLine("数据库鉴权耗时ms：" + stopwatch.Elapsed.TotalMilliseconds);

            bool isPass = parm == null;

            stopwatch.Restart();

            (bool IsAuth, bool IsPass) r = (CheckAuth(context, parm), isPass);

            stopwatch.Stop();
            Console.WriteLine("通用鉴权耗时ms：" + stopwatch.Elapsed.TotalMilliseconds);

            return r;
        }

        /// <summary>
        /// 默认鉴权
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public bool CheckAuthDefault(HttpContext context)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            bool isAccess = CheckAuth(context, _authOptions.WatchAccessControlEndPoints);
            stopwatch.Stop();
            Console.WriteLine("默认鉴权耗时ms:" + stopwatch.ElapsedMilliseconds);

            return isAccess;
        }

        /// <summary>
        /// 通用鉴权方法
        /// </summary>
        /// <param name="context"></param>
        /// <param name="authEndPoints">授权节点列表</param>
        /// <returns></returns>
        public bool CheckAuth(HttpContext context, IAuthEndPointAttribute[] authEndPoints)
        {

            if (authEndPoints == null || authEndPoints.Length < 1)
            {
                return false;
            }

            string controllerName = context.GetRouteValue(AuthOptions.CONTROLLER)?.ToString().ToLower();
            string actionName = context.GetRouteValue(AuthOptions.ACTION)?.ToString().ToLower();
            if (string.IsNullOrEmpty(controllerName) || string.IsNullOrEmpty(actionName))
            {
                //不在监听范围
                return true;
            }



            #region 精确匹配权限节点
            //搜索节点，路由标记不为空、Http请求方法符合标记的请求方法
            IEnumerable<AuthEndPointAttribute> authEndpoints = authEndPoints.Where(x => x is AuthEndPointAttribute).Select(x => x as AuthEndPointAttribute);
            if (authEndpoints.Count() < 1)
            {
                // 精确节点标记为空，尝试匹配正则
                goto RegexMatch;
            }

            string method = context.Request?.Method?.ToUpper();
            if (string.IsNullOrEmpty(method))
            {
                return false;
            }

            //查找请求方法限定
            var matcheps = authEndpoints.Where(x => x.Routes != null && x.Routes.Any(y => y.HttpMethods.Any(z => z?.ToUpper() == method)));
            //搜索节点，忽略Controller大小写、Action匹配小写
            AuthEndPointAttribute allowep = matcheps.FirstOrDefault(x =>
            x.ControllerName.IndexOf(controllerName, StringComparison.CurrentCultureIgnoreCase) == 0 &&
            x.ActionName?.ToLower() == actionName);

            //允许访问
            bool? isAllow = allowep?.IsAllow;
            bool? allowGuest = allowep?.AllowGuest;
            if ((allowGuest.HasValue && allowGuest.Value) || (isAllow.HasValue && isAllow.Value))
            {
                return true;
            }

            //当被访问的Action没有标记授权节点时，查找Controller授权节点
            if (allowep == null)
            {
                var allowAll = authEndpoints.FirstOrDefault(x => x.ControllerName?.ToLower() == controllerName.ToLower() + AuthOptions.CONTROLLER && x.ActionName == "*");
                var isAllowAll = allowAll?.IsAllow;
                var allowGuestAll = allowAll?.AllowGuest;

                if ((allowGuestAll.HasValue && allowGuestAll.Value) || (isAllowAll.HasValue && isAllowAll.Value))
                {
                    return true;
                }
            }
            #endregion


            //正则匹配节点
            RegexMatch:
            #region 正则匹配节点
            IEnumerable<AuthEnableRegexAttribute> regexAuthEndpoints = authEndPoints.Where(x => x is AuthEnableRegexAttribute).Select(x => x as AuthEnableRegexAttribute).ToArray();
            if (regexAuthEndpoints.Count() < 1)
            {
                return false;
            }
            string regexInput = $"{controllerName}.{actionName}";
            bool hasAllow = regexAuthEndpoints.Where(x => x.Regex != null && x.Regex.IsMatch(regexInput) && (x.AllowGuest || x.IsAllow)).Any();

            return hasAllow;
            #endregion


            //return false;
        }

        #endregion

        #region 默认获取权限节点方法

        ///// <summary>
        ///// 从缓存获取权限节点
        ///// </summary>
        ///// <returns></returns>
        //public static AuthEndPointAttribute[] DefaultExtractCacheAuthEndPoints()
        //{
        //    return null;
        //}

        ///// <summary>
        ///// 从数据库获取权限节点
        ///// </summary>
        ///// <returns></returns>
        //public static AuthEndPointAttribute[] DefaultExtractDatabaseAuthEndPoints()
        //{
        //    return null;
        //}
        #endregion

        #region 获取Token

        /// <summary>
        /// Get credential by querystring
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public virtual string GetAuthQuery(HttpContext context, string key)
        {
            StringValues vs = default(StringValues);
            context.Request.Query?.TryGetValue(key, out vs);
            var token = vs.ToString();

            return token;
        }

        /// <summary>
        /// Get credential by request header
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public virtual string GetAuthHeader(HttpContext context, string key)
        {
            StringValues vs = default(StringValues);
            context.Request.Headers?.TryGetValue(key, out vs);
            var token = vs.ToString();

            return token;
        }

        /// <summary>
        /// Get credential by cookie
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public virtual string GetAuthCookie(HttpContext context, string key)
        {
            string token = string.Empty;
            context.Request.Cookies?.TryGetValue(key, out token);

            return token;
        }
        #endregion

        #region 辅助方法
        /// <summary>
        /// 获取授权Key
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public string GetAuthorizationValue(HttpContext context)
        {
            var key = _authOptions.SourceKey;
            string authKey;

            try
            {
                // 搜索凭据位置
                switch (_authOptions.SourceLocation)
                {
                    case Microsoft.OpenApi.Models.ParameterLocation.Query:
                        authKey = GetAuthQuery(context, key);
                        break;
                    case Microsoft.OpenApi.Models.ParameterLocation.Header:
                        authKey = GetAuthHeader(context, key);
                        break;
                    case Microsoft.OpenApi.Models.ParameterLocation.Path:
                        throw new NotSupportedException("不支持从“Path”搜索凭据");
                    case Microsoft.OpenApi.Models.ParameterLocation.Cookie:
                        authKey = GetAuthCookie(context, key);
                        break;
                    default:
                        throw new NotSupportedException("不支持从该位置搜索凭据");
                }
            }
            catch (Exception)
            {

                throw;
            }

            return authKey;
        }

        /// <summary>
        /// 缓存注册权限节点
        /// </summary>
        /// <param name="accessCode"></param>
        /// <param name="isAccept"></param>
        public void RegisterAccessCode(string accessCode, bool isAccept)
        {
            try
            {
                var accs = _memoryCache.GetOrCreate<Dictionary<string, bool>>("Cyaim_AuthEndPoints", x => new Dictionary<string, bool>());

                accs.TryAdd(accessCode, isAccept);

                _memoryCache.Set("authEndPoints", accs, cacheEntryOptions);
            }
            catch (Exception)
            {

                throw;
            }
        }

        #endregion

    }
}
