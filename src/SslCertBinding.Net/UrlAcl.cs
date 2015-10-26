using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using URLACL_QUERY = SslCertBinding.Net.HttpApi.HTTP_SERVICE_CONFIG_URLACL_QUERY;
using URLACL_QUERY_TYPE = SslCertBinding.Net.HttpApi.HTTP_SERVICE_CONFIG_QUERY_TYPE;
using URLACL_SET = SslCertBinding.Net.HttpApi.HTTP_SERVICE_CONFIG_URLACL_SET;

namespace SslCertBinding.Net
{
    public sealed class UrlAcl
    {
        public string Prefix { get; private set; }

        public string Sddl { get; private set; }

        private UrlAcl(string prefix, string sddl)
        {
            this.Prefix = prefix;
            this.Sddl = sddl;
        }

        public static UrlAcl Create(string prefix, string newSddl)
        {
            HttpApi.CallHttpApi(() =>
            {
                var config = new URLACL_SET();
                config.KeyDesc.pUrlPrefix = prefix;
                config.ParamDesc.pStringSecurityDescriptor = newSddl;

                HttpApi.ThrowWin32ExceptionIfError(HttpApi.HttpSetServiceConfiguration(IntPtr.Zero,
                    HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigUrlAclInfo,
                    config, Marshal.SizeOf(config), IntPtr.Zero));
            });

            return new UrlAcl(prefix, newSddl);
        }

        public static void Delete(string prefix)
        {
            HttpApi.CallHttpApi(() =>
            {
                var configKey = new URLACL_SET();
                configKey.KeyDesc.pUrlPrefix = prefix;

                HttpApi.ThrowWin32ExceptionIfError(HttpApi.HttpDeleteServiceConfiguration(IntPtr.Zero, 
                    HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigUrlAclInfo, 
                    configKey, Marshal.SizeOf(configKey), IntPtr.Zero));
            });
        }

        public static IEnumerable<UrlAcl> GetAllBindings()
        {
            HttpApi.ThrowWin32ExceptionIfError(HttpApi.HttpInitialize(
                HttpApi.HttpApiVersion, HttpApi.HTTP_INITIALIZE_CONFIG, IntPtr.Zero));
            try
            {
                var szQuery = Marshal.SizeOf(typeof(URLACL_QUERY));
                var pQuery = Marshal.AllocHGlobal(szQuery);
                var szOutputBuffer = 4096;
                const int szMaxOutputBuffer = 4194304 /* 4 mb */;
                var pOutputBuffer = Marshal.AllocHGlobal(szOutputBuffer);

                try
                {
                    for (int i = 0; i < int.MaxValue; i++)
                    {
                        // setup the query
                        var query = new URLACL_QUERY();
                        query.dwToken = i;
                        query.QueryDesc = URLACL_QUERY_TYPE.HttpServiceConfigQueryNext;
                        Marshal.StructureToPtr(query, pQuery, false);

                        while (true)
                        {
                            int szRequiredOutputBuffer;
                            var result = HttpApi.HttpQueryServiceConfiguration(IntPtr.Zero,
                                HttpApi.HTTP_SERVICE_CONFIG_ID.HttpServiceConfigUrlAclInfo,
                                pQuery, szQuery, pOutputBuffer, szOutputBuffer, out szRequiredOutputBuffer, IntPtr.Zero);

                            if (result == HttpApi.ERROR_NO_MORE_ITEMS)
                            {
                                yield break;
                            }
                            else if (result == HttpApi.ERROR_INSUFFICIENT_BUFFER)
                            {
                                if (szOutputBuffer >= szMaxOutputBuffer)
                                {
                                    throw new InvalidOperationException();
                                }

                                Marshal.FreeHGlobal(pOutputBuffer);
                                Marshal.AllocHGlobal(szOutputBuffer *= 2);
                                continue;
                            }
                            else if (result == HttpApi.NO_ERROR)
                            {
                                break;
                            }
                            else
                            {
                                throw new Win32Exception((int)result);
                            }
                        }

                        var output = (URLACL_SET)Marshal.PtrToStructure(pOutputBuffer, typeof(URLACL_SET));
                        yield return new UrlAcl(output.KeyDesc.pUrlPrefix, output.ParamDesc.pStringSecurityDescriptor);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pQuery);
                    Marshal.FreeHGlobal(pOutputBuffer);
                }
            }
            finally
            {
                HttpApi.HttpTerminate(HttpApi.HTTP_INITIALIZE_CONFIG, IntPtr.Zero);
            }
        }
    }
}
