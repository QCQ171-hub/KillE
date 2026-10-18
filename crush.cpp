// crush.exe — Windows 文件粉碎工具 (命令行 / 可双击 .cmd 启动)
// 流程: 循环 { 扫描 -> 删除未占用文件 -> 枚举句柄找出占用进程 -> 强制结束 } 直到目录内不剩(匹配)文件。
// 构建见 CMakeLists.txt。核心依赖: kernel32 / advapi32 / shell32 / ntdll(动态解析)。
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <restartmanager.h>

// ============ 前向声明 ============
static void      printW(const std::wstring& s);
static std::wstring u82w(const std::string& s);
static std::string w2u8(const std::wstring& s);

// ============ console ============
static std::wstring u82w(const std::string& s){
    if(s.empty()) return L"";
    int n=MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),nullptr,0);
    std::wstring w(n,0); MultiByteToWideChar(CP_UTF8,0,s.c_str(),(int)s.size(),w.data(),n); return w;
}
static std::string w2u8(const std::wstring& w){
    if(w.empty()) return "";
    int n=WideCharToMultiByte(CP_UTF8,0,w.c_str(),(int)w.size(),nullptr,0,nullptr,nullptr);
    std::string s(n,0); WideCharToMultiByte(CP_UTF8,0,w.c_str(),(int)w.size(),s.data(),n,nullptr,nullptr); return s;
}
static bool g_isConsole=false;
static void printW(const std::wstring& s){
    if(g_isConsole){
        HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD w=0; WriteConsoleW(h,s.c_str(),(DWORD)s.size(),&w,nullptr);
    } else {
        std::string u=w2u8(s); fwrite(u.data(),1,u.size(),stdout); fflush(stdout);
    }
}
static void printlnW(const std::wstring& s){ printW(s); printW(L"\r\n"); }

// 读取一行(返回 utf-8)。用 ReadFile 读控制台原始字节，避免 CRT 与代码页问题。
static std::string readLine(){
    std::string line; char c; DWORD n=0;
    HANDLE h=GetStdHandle(STD_INPUT_HANDLE);
    for(;;){
        if(!ReadFile(h,&c,1,&n,nullptr)||n==0) break;
        if(c=='\n') break;
        if(c!='\r') line+=c;
    }
    return line;
}

// ============ paths ============
static std::wstring upperCopy(std::wstring s){ for(auto&c:s) if(c>=L'a'&&c<=L'z') c-=32; return s; }
static std::wstring fullNormalized(const std::wstring& p){
    wchar_t buf[8192];
    DWORD r=GetFullPathNameW(p.c_str(),8192,buf,nullptr);
    std::wstring out = r? std::wstring(buf,r): p;
    for(auto&c:out) if(c==L'/') c=L'\\';
    // 去掉末尾反斜杠(盘根除外)
    while(out.size()>3 && out.back()==L'\\') out.pop_back();
    return out;
}
static std::wstring baseName(const std::wstring& p){ size_t s=p.find_last_of(L"\\/"); return s==std::wstring::npos? p : p.substr(s+1); }
static std::wstring extOf(const std::wstring& p){
    std::wstring b=baseName(p); size_t d=b.find_last_of(L'.');
    if(d==std::wstring::npos || d==0) return L"";      // 无扩展名
    return b.substr(d);                                  // 含点, 原样
}
static std::wstring fmtSize(unsigned long long bytes){
    static const wchar_t* u[]={L"B",L"KB",L"MB",L"GB",L"TB"};
    int i=0; double v=(double)bytes;
    while(v>=1024.0 && i<4){ v/=1024.0; ++i; }
    wchar_t b[64];
    if(i==0) swprintf(b,64,L"%llu ",(unsigned long long)bytes);
    else     swprintf(b,64,L"%.1f ",v);
    std::wstring r=b; r+=u[i]; return r;
}

// ============ scan ============
struct FileInfo { std::wstring path; unsigned long long size; };
static void scanTree(const std::wstring& root, std::vector<FileInfo>& out){
    std::wstring pat=root+L"\\*";
    WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(pat.c_str(),&fd);
    if(h==INVALID_HANDLE_VALUE) return;
    do{
        std::wstring name=fd.cFileName;
        if(name==L"."||name==L"..") continue;
        std::wstring full=root+L"\\"+name;
        if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
            scanTree(full,out);
        } else {
            unsigned long long sz=((unsigned long long)fd.nFileSizeHigh<<32)|fd.nFileSizeLow;
            out.push_back({full,sz});
        }
    }while(FindNextFileW(h,&fd));
    FindClose(h);
}

// ============ delete ============
// 原生删除: 先清只读再 DeleteFileW；返回 true=已删除或本就不存在; 否则 false 且 *lastErr 为失败码
static bool nativeDelete(const std::wstring& p, DWORD* lastErr){
    for(int t=0;t<3;++t){
        SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL);
        if(DeleteFileW(p.c_str())) return true;
        DWORD e=GetLastError();
        if(e==ERROR_FILE_NOT_FOUND||e==ERROR_PATH_NOT_FOUND) return true; // 已没了
        if(e==ERROR_ACCESS_DENIED||e==ERROR_SHARING_VIOLATION){ if(lastErr)*lastErr=e; return false; }
        if(lastErr)*lastErr=e;
        Sleep(50);
    }
    return false;
}
// 命令删除: cmd /c del /f /q "path"。返回 true=del 成功(退出码0)
static std::wstring quoteCmd(const std::wstring& s){ return L"\""+s+L"\""; }
static int runHidden(const std::wstring& exe, const std::wstring& args){
    std::wstring cl=quoteCmd(exe)+(args.empty()?L"":(L" "+args));
    std::vector<wchar_t> buf(cl.begin(),cl.end()); buf.push_back(0);
    STARTUPINFOW si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi{};
    if(!CreateProcessW(nullptr,buf.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi))
        return -1;
    WaitForSingleObject(pi.hProcess,15000);
    DWORD code=1; GetExitCodeProcess(pi.hProcess,&code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)code;
}
static bool cmdDelete(const std::wstring& p){
    // del 命令即使删不掉(文件被占用)也会返回退出码0, 不可信; 以"文件是否还在"为准
    runHidden(L"cmd.exe", L"/c del /f /q "+quoteCmd(p));
    return GetFileAttributesW(p.c_str())==INVALID_FILE_ATTRIBUTES;
}

// ============ locker (找出占用某文件的进程) ============
struct LockMaps { std::map<std::wstring, std::set<DWORD>> byPath; };

static bool startsInside(const std::wstring& pathUpper, const std::wstring& rootUpper){
    if(pathUpper.size()<=rootUpper.size()) return false;
    if(pathUpper.compare(0,rootUpper.size(),rootUpper)!=0) return false;
    return rootUpper.back()==L'\\' ? true : pathUpper[rootUpper.size()]==L'\\';
}

// 1) 模块快照: 目标树内的 exe/dll -> 加载它的 PID (覆盖"正在运行的程序/已加载的库")
static void buildModuleMap(const std::wstring& rootUpper, LockMaps& m){
    DWORD self=GetCurrentProcessId();
    HANDLE sp=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(sp==INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{}; pe.dwSize=sizeof(pe);
    if(Process32FirstW(sp,&pe)){
        do{
            if(pe.th32ProcessID==self||pe.th32ProcessID==0||pe.th32ProcessID==4) continue;
            HANDLE ms=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pe.th32ProcessID);
            if(ms!=INVALID_HANDLE_VALUE){
                MODULEENTRY32W me{}; me.dwSize=sizeof(me);
                if(Module32FirstW(ms,&me)){
                    do{ std::wstring p=upperCopy(fullNormalized(me.szExePath));
                        if(startsInside(p,rootUpper)) m.byPath[p].insert(pe.th32ProcessID);
                    }while(Module32NextW(ms,&me));
                }
                CloseHandle(ms);
            }
        }while(Process32NextW(sp,&pe));
    }
    CloseHandle(sp);
}

// 2) Restart Manager: 精确列出锁住该文件的进程 PID。系统为"查找占用文件的进程"专门提供的
//    API, 无需句柄枚举(那会因个别句柄 NtQueryObject 永久阻塞), 也不需管理员权限。
static std::set<DWORD> rmLockersOfFile(const std::wstring& path){
    std::set<DWORD> out; DWORD self=GetCurrentProcessId();
    DWORD sess=0; WCHAR key[CCH_RM_SESSION_KEY+1]; ZeroMemory(key,sizeof(key));
    if(RmStartSession(&sess,0,key)!=ERROR_SUCCESS) return out;
    LPCWSTR files[1]; files[0]=path.c_str();
    if(RmRegisterResources(sess,1,files,0,nullptr,0,nullptr)==ERROR_SUCCESS){
        UINT need=0,got=0; DWORD reason=0;
        DWORD rc=RmGetList(sess,&need,&got,nullptr,&reason);
        if((rc==ERROR_SUCCESS||rc==ERROR_MORE_DATA)&&need>0){
            std::vector<RM_PROCESS_INFO> arr(need); got=need;   // 填入调用前, got 必须=数组容量
            if(RmGetList(sess,&need,&got,arr.data(),&reason)==ERROR_SUCCESS){
                for(UINT i=0;i<got && i<need;++i){
                    DWORD p=arr[i].Process.dwProcessId;
                    if(p!=self&&p!=0&&p!=4) out.insert(p);
                }
            }
        }
    }
    RmEndSession(sess);
    return out;
}
static std::wstring procNameById(DWORD pid){
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!h) return L"";
    wchar_t path[MAX_PATH*4]; DWORD n=(DWORD)(sizeof(path)/sizeof(path[0]));
    std::wstring name=L"(unknown)";
    if(QueryFullProcessImageNameW(h,0,path,&n)){ std::wstring p(path,n); name=baseName(p); }
    else {
        HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,pid); PROCESSENTRY32W e{}; e.dwSize=sizeof(e);
        if(Process32FirstW(s,&e)){ do{ if(e.th32ProcessID==pid){ name=e.szExeFile; break; } }while(Process32NextW(s,&e)); }
        CloseHandle(s);
    }
    CloseHandle(h); return name;
}

// ============ kill ============
static bool nativeKill(DWORD pid){
    HANDLE h=OpenProcess(PROCESS_TERMINATE|SYNCHRONIZE,FALSE,pid);
    if(!h) return false;
    BOOL ok=TerminateProcess(h,0);
    WaitForSingleObject(h,3000);
    CloseHandle(h); return ok==TRUE;
}
static bool cmdKill(const std::wstring& imageName){
    return runHidden(L"taskkill.exe", L"/f /t /im "+quoteCmd(imageName))==0;
}

// ============ progress ============
static size_t g_lastBarLen=0;
static void showProgress(size_t done, size_t total, const std::wstring& phase){
    if(!g_isConsole){ return; }
    static const int BW=28;
    float frac = total? (float)done/(float)total : 1.0f;
    int fill=(int)(frac*BW); if(fill>BW) fill=BW;
    std::wstring bar=L"["; for(int i=0;i<BW;++i) bar+= (i<fill? L'#':L'.'); bar+=L"]";
    wchar_t pct[32]; swprintf(pct,32,L"%3d%%", (int)(frac*100+0.5f));
    wchar_t cnt[48]; swprintf(cnt,48,L" %llu/%llu", (unsigned long long)done,(unsigned long long)total);
    std::wstring line=L"\r  "+phase+L" "+bar+L" "+pct+cnt;
    size_t pad = line.size()>g_lastBarLen? 0 : g_lastBarLen-line.size();
    line.append(pad,L' ');
    g_lastBarLen=line.size();
    printW(line);
    if(done>=total){ printW(L"\r\n"); g_lastBarLen=0; }
}
static void clearProgress(){ if(g_lastBarLen){ printW(L"\r"); printW(std::wstring(g_lastBarLen,L' ')); printW(L"\r"); g_lastBarLen=0; } }

// ============ report ============
static const size_t TOPN=10;
static void reportDeleted(const std::vector<FileInfo>& del){
    if(del.empty()){ printlnW(L"  本轮删除: 无"); return; }
    std::vector<FileInfo> v=del;
    std::sort(v.begin(),v.end(),[](const FileInfo&a,const FileInfo&b){return a.size>b.size;});
    std::wstring s=L"  删除 "+std::to_wstring(del.size())+L" 个文件: ";
    size_t n=std::min(v.size(),TOPN);
    for(size_t i=0;i<n;++i){ s+=baseName(v[i].path)+L"("+fmtSize(v[i].size)+L")"; if(i+1<n) s+=L", "; }
    if(v.size()>TOPN) s+=L" 等";
    printlnW(s);
}
static void reportKilled(const std::vector<std::pair<DWORD,std::wstring>>& kp){
    if(kp.empty()) return;
    std::wstring s=L"  结束 "+std::to_wstring(kp.size())+L" 个占用进程: ";
    size_t n=std::min(kp.size(),TOPN);
    for(size_t i=0;i<n;++i){
        s += kp[i].second + L"(PID " + std::to_wstring((unsigned long)kp[i].first) + L")";
        if(i+1<n) s+=L", ";
    }
    if(kp.size()>TOPN) s+=L" 等";
    printlnW(s);
}
static void reportStuck(const std::vector<FileInfo>& stuck){
    if(stuck.empty()) return;
    std::wstring s=L"  ! 无法删除 "+std::to_wstring(stuck.size())+L" 个文件(未找到占用进程, 可能权限/只读/系统占用): ";
    size_t n=std::min(stuck.size(),TOPN);
    for(size_t i=0;i<n;++i){ s+=baseName(stuck[i].path); if(i+1<n) s+=L", "; }
    if(stuck.size()>TOPN) s+=L" 等";
    printlnW(s);
}

// ============ main ============
struct Config {
    std::wstring target, targetUpper;
    std::set<std::wstring> white, black;   // 小写扩展名, 不含点
    bool useCmd=false, assumeYes=false, help=false;
    bool fatal=false; std::wstring err;
};

static std::wstring normExt(std::wstring e){
    while(!e.empty() && (e[0]==L'.'||e[0]==L'*'||e[0]==L' ')) e.erase(e.begin());
    for(auto&c:e) if(c>=L'A'&&c<=L'Z') c+=32;
    return e;
}
static bool launchedDirectly(){
    DWORD pids[32]; DWORD n=GetConsoleProcessList(pids,32); return n<=1; // 双击/独立控制台
}

static void printHelp(){
    printlnW(
      L"crush.exe — Windows 文件粉碎工具\n"
      L"\n"
      L"用法: crush <目标目录> [/*.后缀 ...] [/*!*后缀 ...] [/cmd] [/y]\n"
      L"\n"
      L"  <目标目录>      必填, 要递归粉碎的目录(可相对路径; 不存在或非目录会报错)\n"
      L"  /*.ext  /*txt   白名单: 仅删除这些扩展名(可多次或逗号分隔 /*.txt,log)\n"
      L"                    省略白名单 = 删除目录内全部文件\n"
      L"  /*!*.ext        黑名单: 排除这些扩展名(不删除), 可多次/逗号\n"
      L"                    同一扩展名同时出现在白/黑名单 => 报错\n"
      L"  /cmd            用外部命令: del /f /q 删除 + taskkill /f /im 结束进程\n"
      L"                    (默认用 Win32 API: DeleteFileW + TerminateProcess)\n"
      L"  /y              跳过二次确认(默认需输入 YES)\n"
      L"  /?  /h          显示本帮助\n"
      L"\n"
      L"删除流程: 反复[扫描->删除未被占用文件->用重启管理器(RM)定位占用进程并强制结束->下一轮]直到目标内不剩匹配文件。\n"
      L"示例: crush D:\\temp /*.tmp,log /cmd\n"
    );
}

static Config parseArgs(int argc, wchar_t** argv){
    Config c;
    auto addExt=[&](std::wstring tok, bool black){
        // tok 形如 ".txt" 或 "a,b,c"
        size_t pos=0; 
        do{
            size_t comma=tok.find(L',',pos);
            std::wstring piece = comma==std::wstring::npos? tok.substr(pos): tok.substr(pos,comma-pos);
            std::wstring e=normExt(piece);
            if(!e.empty()){ (black? c.black:c.white).insert(e); }
            pos = comma==std::wstring::npos? tok.size() : comma+1;
        }while(pos<tok.size());
    };
    for(int i=1;i<argc;++i){
        std::wstring a=argv[i];
        if(!a.empty() && a[0]==L'/'){
            if(a.rfind(L"/*!*",0)==0){ addExt(a.substr(4),true); continue; }
            if(a.rfind(L"/*",0)==0){ addExt(a.substr(2),false); continue; }
            std::wstring k=a.substr(1); for(auto&x:k) if(x>=L'A'&&x<=L'Z') x+=32;
            if(k==L"cmd"){ c.useCmd=true; }
            else if(k==L"y"){ c.assumeYes=true; }
            else if(k==L"?"||k==L"h"||k==L"help"){ c.help=true; }
            else { c.fatal=true; c.err=L"未知开关: "+a; return c; }
        } else if(a==L"-?"||a==L"--help"||a==L"-h"){ c.help=true; }
        else {
            if(!c.target.empty()){ c.fatal=true; c.err=L"只能指定一个目标目录: 已有 ["+c.target+L"] 又出现 ["+a+L"]"; return c; }
            c.target=a;
        }
    }
    // 白黑冲突检测
    std::vector<std::wstring> conf; for(auto&e:c.white) if(c.black.count(e)) conf.push_back(e);
    if(!conf.empty()){
        c.fatal=true; std::wstring s=L"白名单与黑名单冲突的扩展名: ";
        for(size_t i=0;i<conf.size();++i){ s+=L"."+conf[i]; if(i+1<conf.size()) s+=L", "; }
        c.err=s; return c;
    }
    if(c.help) return c;
    if(c.target.empty()){ c.fatal=true; c.err=L"缺少目标目录(必填)。用 /? 查看帮助。"; return c; }
    c.target=fullNormalized(c.target);
    DWORD at=GetFileAttributesW(c.target.c_str());
    if(at==INVALID_FILE_ATTRIBUTES || !(at&FILE_ATTRIBUTE_DIRECTORY)){
        c.fatal=true; c.err=L"目标不是存在的目录: "+c.target; return c;
    }
    c.targetUpper=upperCopy(c.target);
    return c;
}

static bool included(const std::wstring& path, const Config& c){
    std::wstring e=extOf(path); if(!e.empty() && e[0]==L'.') e.erase(e.begin());
    for(auto&x:e) if(x>=L'A'&&x<=L'Z') x+=32;
    if(c.black.count(e)) return false;                 // 黑名单优先排除
    if(!c.white.empty() && !c.white.count(e)) return false; // 白名单存在则必须命中
    return true;
}

int wmain(int argc, wchar_t** argv){
    SetConsoleOutputCP(65001); SetConsoleCP(65001);
    { HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE); DWORD m=0; g_isConsole = (h&&h!=INVALID_HANDLE_VALUE)&&GetConsoleMode(h,&m); }

    Config c = parseArgs(argc,argv);
    if(c.help){ printHelp(); return 0; }
    if(c.fatal){ printlnW(L"错误: "+c.err); printlnW(L"用 /? 查看帮助。"); return 2; }

    // 预扫描统计
    std::vector<FileInfo> all0; scanTree(c.target, all0);
    std::vector<FileInfo> cand0; for(auto&f:all0) if(included(f.path,c)) cand0.push_back(f);
    unsigned long long sum0=0; for(auto&f:cand0) sum0+=f.size;

    printlnW(L"目标目录 : "+c.target);
    if(!c.white.empty()){ std::wstring s=L"白名单    :"; for(auto&e:c.white) s+=L" ."+e; printlnW(s); }
    else printlnW(L"白名单    : (无 — 删除目录内全部文件)");
    if(!c.black.empty()){ std::wstring s=L"黑名单    :"; for(auto&e:c.black) s+=L" ."+e; printlnW(s); }
    printlnW(L"删除方式  : "+std::wstring(c.useCmd? L"外部命令 del /f + taskkill /f /im" : L"Win32 API DeleteFileW + TerminateProcess"));
    printlnW(L"结束进程  : 系统重启管理器(RM)+模块快照定位占用进程");
    printlnW(L"待粉碎    : "+std::to_wstring(cand0.size())+L" 个匹配文件, 合计 "+fmtSize(sum0));

    if(cand0.empty()){ printlnW(L"没有可删除的文件, 结束。"); if(launchedDirectly()){printW(L"\n按回车退出...");readLine();} return 0; }

    if(!c.assumeYes){
        printlnW(L"");
        printW(L"⚠ 此操作不可恢复! 输入大写 YES 确认执行, 输入其它内容取消: ");
        std::string in=readLine();
        std::wstring w=u82w(in); while(!w.empty() && (w.back()==L' '||w.back()==L'\t')) w.pop_back();
        if(w!=L"YES"){ printlnW(L"已取消, 未做任何删除。"); if(launchedDirectly()){printW(L"\n按回车退出...");readLine();} return 3; }
    }

    size_t totalDeleted=0; int round=0;
    while(true){
        ++round;
        std::vector<FileInfo> files; scanTree(c.target, files);
        std::vector<FileInfo> cand; for(auto&f:files) if(included(f.path,c)) cand.push_back(f);
        if(cand.empty()) break;

        printlnW(L"");
        printlnW(L"— 第 "+std::to_wstring(round)+L" 轮 · 匹配 "+std::to_wstring(cand.size())+L" 个文件");
        std::vector<FileInfo> del, occ;
        size_t done=0;
        for(auto&f:cand){
            bool ok; DWORD err=0;
            if(c.useCmd) ok = cmdDelete(f.path);
            else ok = nativeDelete(f.path,&err);
            if(ok) del.push_back(f); else occ.push_back(f);
            ++done; if(done%8==0 || done==cand.size()) showProgress(done,cand.size(),L"删除中");
        }
        clearProgress();

        std::vector<FileInfo> stuck; std::vector<std::pair<DWORD,std::wstring>> killed;
        if(!occ.empty()){
            LockMaps lm; buildModuleMap(c.targetUpper, lm);   // 覆盖运行中的 exe/dll
            std::set<DWORD> toKill;
            for(auto&f:occ){
                std::set<DWORD> ls = rmLockersOfFile(f.path); // 打开该文件句柄的进程
                auto mit=lm.byPath.find(upperCopy(f.path));
                if(mit!=lm.byPath.end()) for(auto pid:mit->second) ls.insert(pid);
                if(ls.empty()) stuck.push_back(f);
                else for(auto pid:ls) toKill.insert(pid);
            }
            size_t ki=0; std::vector<std::pair<DWORD,std::wstring>> failKill;
            for(DWORD pid:toKill){
                std::wstring nm=procNameById(pid);
                bool k = c.useCmd ? (nm.empty()?false:cmdKill(nm)) : nativeKill(pid);
                ++ki; showProgress(ki,toKill.size(),L"结束占用进程");
                if(k) killed.push_back({pid, nm.empty()?L"(已退出)":nm});
                else failKill.push_back({pid, nm.empty()?L"(未知)":nm});
            }
            if(!failKill.empty()){
                std::wstring s=L"  ! 找到但无法结束 "+std::to_wstring(failKill.size())+L" 个占用进程(权限/系统保护): ";
                size_t n=std::min(failKill.size(),TOPN);
                for(size_t i=0;i<n;++i){ s+=failKill[i].second+L"(PID "+std::to_wstring((unsigned long)failKill[i].first)+L")"; if(i+1<n) s+=L", "; }
                if(failKill.size()>TOPN) s+=L" 等";
                printlnW(s);
            }
        }
        reportDeleted(del); reportKilled(killed); reportStuck(stuck);
        totalDeleted+=del.size();

        if(del.empty() && killed.empty()){
            std::vector<FileInfo> remain; scanTree(c.target,remain);
            std::vector<FileInfo> rc; for(auto&f:remain) if(included(f.path,c)) rc.push_back(f);
            printlnW(L"  本轮无任何进展, 停止。剩余匹配文件 "+std::to_wstring(rc.size())+L" 个无法清除。");
            break;
        }
        if(round>=200){ printlnW(L"  达到最大轮次上限, 停止。"); break; }
    }

    // 收尾: 统计剩余
    std::vector<FileInfo> left; scanTree(c.target,left);
    std::vector<FileInfo> lc; for(auto&f:left) if(included(f.path,c)) lc.push_back(f);
    printlnW(L"");
    printlnW(L"完成: 共删除 "+std::to_wstring(totalDeleted)+L" 个文件; 目标内匹配文件剩余 "+std::to_wstring(lc.size())+L" 个。");
    if(!lc.empty()){ printlnW(L"  (若有剩余, 通常是受系统保护且无法结束占用进程的只读/权限文件)"); }

    if(launchedDirectly()){ printW(L"\n按回车退出..."); readLine(); }
    return lc.empty()? 0 : 1;
}
