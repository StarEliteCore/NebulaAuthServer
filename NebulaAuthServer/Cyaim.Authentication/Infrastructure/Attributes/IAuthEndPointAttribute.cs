using System;
using System.Collections.Generic;
using System.Text;

namespace Cyaim.Authentication.Infrastructure.Attributes
{
    /// <summary>
    /// 鉴权标记接口
    /// </summary>
    public interface IAuthEndPointAttribute : IAuthMetadata
    {
        /// <summary>
        /// 权限节点
        /// </summary>
        string AuthEndPoint { get; set; }

        /// <summary>
        /// 是否允许访问
        /// </summary>
        bool IsAllow { get; set; }

        /// <summary>
        /// 是否允许游客访问
        /// </summary>
        public bool AllowGuest { get; set; }

    }
}
