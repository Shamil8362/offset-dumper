#include "utils.hpp"
#include "pe_parser.hpp"
#include "aob_scanner.hpp"
#include "process.hpp"
#include "pointer_scan.hpp"
#include "offset_dump.hpp"

#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <set>

using namespace OffsetDumper;

static std::string g_id = "0";

static std::string jstr(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        if      (c == '"')  o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else                o += c;
    }
    return o + "\"";
}

static std::string ok(const std::string& data) {
    return "{\"ok\":true,\"_id\":" + g_id + ",\"data\":" + data + "}\n";
}
static std::string err(const std::string& msg) {
    return "{\"ok\":false,\"_id\":" + g_id + ",\"error\":" + jstr(msg) + "}\n";
}

static std::map<std::string,std::string> parse_json(const std::string& line) {
    std::map<std::string,std::string> r;
    size_t i = 0;
    auto ws  = [&](){ while(i<line.size()&&(line[i]==' '||line[i]=='\t'||line[i]=='\r'||line[i]=='\n'))++i; };
    auto rstr= [&]()->std::string{
        if(i>=line.size()||line[i]!='"') return "";
        ++i; std::string s;
        while(i<line.size()&&line[i]!='"'){
            if(line[i]=='\\'&&i+1<line.size()){++i;s+=line[i];}
            else s+=line[i];
            ++i;
        }
        if(i<line.size())++i;
        return s;
    };
    while(i<line.size()){
        ws();
        if(i>=line.size()||line[i]=='}') break;
        if(line[i]=='{'||line[i]==','){++i;continue;}
        if(line[i]!='"'){++i;continue;}
        auto key=rstr(); ws();
        if(i<line.size()&&line[i]==':')++i;
        ws();
        std::string val;
        if(i<line.size()&&line[i]=='"') val=rstr();
        else{ while(i<line.size()&&line[i]!=','&&line[i]!='}') val+=line[i++]; }
        if(!key.empty()) r[key]=val;
    }
    return r;
}

// Collect PIDs that have a REAL visible window (not just a tray icon or hidden helper)
// Criteria: visible, has title, not a tool window, reasonable size
static std::set<DWORD> get_real_windowed_pids() {
    struct Ctx { std::set<DWORD> pids; };
    Ctx ctx;

    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lp);

        // Must be visible
        if (!IsWindowVisible(hwnd)) return TRUE;

        // Must have a non-empty title
        wchar_t title[256] = {};
        int titleLen = GetWindowTextW(hwnd, title, 256);
        if (titleLen == 0) return TRUE;

        // Skip tool windows (tray icons, tooltips, etc.)
        LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
        if (exStyle & WS_EX_TOOLWINDOW) return TRUE;

        // Must have a parent == NULL (top-level window)
        if (GetWindow(hwnd, GW_OWNER) != NULL) return TRUE;

        // Must have reasonable size (not 0x0 or 1x1 invisible windows)
        RECT rect = {};
        GetWindowRect(hwnd, &rect);
        int w = rect.right - rect.left;
        int h = rect.bottom - rect.top;
        if (w < 50 || h < 50) return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid) c->pids.insert(pid);
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));

    return ctx.pids;
}

static std::string cmd_list_processes() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snap==INVALID_HANDLE_VALUE) return err("Snapshot failed");

    auto windowed = get_real_windowed_pids();

    PROCESSENTRY32W e{}; e.dwSize=sizeof(e);
    std::ostringstream o;
    o << "[";
    bool first=true;
    if(Process32FirstW(snap,&e)){
        do {
            std::string name=wide_to_narrow(e.szExeFile);
            bool active = windowed.count(e.th32ProcessID) > 0;
            if(!first) o<<",";
            first=false;
            o<<"{"
             <<"\"pid\":"<<e.th32ProcessID
             <<",\"name\":"<<jstr(name)
             <<",\"active\":"<<(active?"true":"false")
             <<"}";
        } while(Process32NextW(snap,&e));
    }
    CloseHandle(snap);
    o<<"]";
    return ok(o.str());
}

static std::string cmd_scan_file(const std::map<std::string,std::string>& a) {
    auto fi=a.find("file"), pi=a.find("pattern");
    if(fi==a.end()) return err("Missing 'file'");
    PEParser parser;
    if(!parser.load(fi->second)||!parser.is_valid())
        return err("Failed to load PE: "+fi->second);
    std::ostringstream o;
    o<<"{"
     <<"\"imageBase\":"<<jstr(to_hex(parser.get_image_base()))
     <<",\"entryPoint\":"<<jstr(to_hex(parser.get_entry_point()))
     <<",\"arch\":"<<jstr(parser.is_64bit()?"x64":"x86");
    auto secs=parser.get_sections();
    o<<",\"sections\":[";
    for(size_t i=0;i<secs.size();++i){
        const auto& s=secs[i];
        if(i) o<<",";
        o<<"{"
         <<"\"name\":"<<jstr(s.name)
         <<",\"va\":"<<jstr(to_hex(s.virtual_address))
         <<",\"size\":"<<jstr(to_hex(s.virtual_size))
         <<",\"rawOffset\":"<<jstr(to_hex(s.raw_offset))
         <<",\"characteristics\":"<<jstr(to_hex(s.characteristics))
         <<"}";
    }
    o<<"]";
    if(pi!=a.end()&&!pi->second.empty()){
        o<<",\"matches\":[";
        bool first=true;
        try {
            AOBScanner::parse_pattern(pi->second);
            for(const auto& sec:secs){
                auto data=parser.read_section_data(sec);
                if(data.empty()) continue;
                for(size_t off:AOBScanner::scan_buffer(data.data(),data.size(),pi->second)){
                    uintptr_t rva=sec.virtual_address+off;
                    if(!first) o<<",";
                    first=false;
                    o<<"{"
                     <<"\"rva\":"<<jstr(to_hex(rva))
                     <<",\"section\":"<<jstr(sec.name);
                    if(data.size()>=off+7){
                        auto rip=AOBScanner::extract_rip_relative(data.data(),data.size(),off,3,7);
                        if(rip.has_value())
                            o<<",\"ripTarget\":"<<jstr(to_hex(sec.virtual_address+rip.value()));
                    }
                    o<<"}";
                }
            }
        } catch(...){ return err("Invalid pattern"); }
        o<<"]";
    }
    o<<"}";
    return ok(o.str());
}

static std::string cmd_scan_process(const std::map<std::string,std::string>& a) {
    auto pi=a.find("process"), pati=a.find("pattern");
    if(pi==a.end()) return err("Missing 'process'");
    Process proc;
    if(!proc.attach(pi->second)) return err("Failed to attach: "+pi->second);
    auto main_mod=proc.get_main_module();
    auto modules=proc.get_modules();
    std::ostringstream o;
    o<<"{"
     <<"\"mainModule\":"<<jstr(main_mod?main_mod->name:"?")
     <<",\"mainBase\":"<<jstr(main_mod?to_hex(main_mod->base):"?");
    o<<",\"modules\":[";
    for(size_t i=0;i<modules.size();++i){
        if(i) o<<",";
        o<<"{"
         <<"\"name\":"<<jstr(modules[i].name)
         <<",\"base\":"<<jstr(to_hex(modules[i].base))
         <<",\"size\":"<<jstr(to_hex(modules[i].size))
         <<"}";
    }
    o<<"]";
    if(pati!=a.end()&&!pati->second.empty()){
        o<<",\"matches\":[";
        bool first=true;
        try {
            AOBScanner::parse_pattern(pati->second);
            for(const auto& region:proc.get_memory_regions(true)){
                auto data=proc.read_memory_vec(region.base,region.size);
                if(data.empty()) continue;
                for(size_t off:AOBScanner::scan_buffer(data.data(),data.size(),pati->second)){
                    uintptr_t addr=region.base+off;
                    if(!first) o<<",";
                    first=false;
                    o<<"{\"address\":"<<jstr(to_hex(addr));
                    if(main_mod&&addr>=main_mod->base&&addr<main_mod->base+main_mod->size)
                        o<<",\"rva\":"<<jstr(to_hex(addr-main_mod->base));
                    o<<"}";
                }
            }
        } catch(...){ proc.detach(); return err("Invalid pattern"); }
        o<<"]";
    }
    proc.detach();
    o<<"}";
    return ok(o.str());
}

static std::string cmd_resolve_chain(const std::map<std::string,std::string>& a) {
    auto pi=a.find("process"), ci=a.find("chain");
    if(pi==a.end()||ci==a.end()) return err("Missing args");
    std::vector<uintptr_t> vals;
    std::istringstream ss(ci->second);
    std::string tok;
    while(std::getline(ss,tok,':')){
        if(tok.empty()) continue;
        try{ vals.push_back(std::stoull(tok,nullptr,16)); }
        catch(...){ return err("Invalid hex: "+tok); }
    }
    if(vals.empty()) return err("Empty chain");
    Process proc;
    if(!proc.attach(pi->second)) return err("Failed to attach: "+pi->second);
    auto main_mod=proc.get_main_module();
    std::string mod=main_mod?main_mod->name:pi->second;
    PointerScanner scanner(proc);
    auto res=scanner.resolve_chain_from_module(mod,vals[0],
        std::vector<uintptr_t>(vals.begin()+1,vals.end()));
    proc.detach();
    std::ostringstream o;
    o<<"{"
     <<"\"valid\":"<<(res.valid?"true":"false")
     <<",\"finalAddress\":"<<jstr(to_hex(res.final_address))
     <<",\"module\":"<<jstr(res.module_name)
     <<",\"baseOffset\":"<<jstr(to_hex(res.base_offset))
     <<"}";
    return ok(o.str());
}

// Write .hpp file to disk
static std::string cmd_export_hpp(const std::map<std::string,std::string>& a) {
    auto pi = a.find("path");
    auto ci = a.find("content");
    if(pi==a.end()||ci==a.end()) return err("Missing path or content");
    FILE* fp = std::fopen(pi->second.c_str(),"w");
    if(!fp) return err("Cannot open file: "+pi->second);
    std::fwrite(ci->second.data(),1,ci->second.size(),fp);
    std::fclose(fp);
    return ok("true");
}

static std::string cmd_batch_scan(const std::map<std::string,std::string>& a);
static std::string cmd_netvar_dump(const std::map<std::string,std::string>& a);

int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    setvbuf(stdout,nullptr,_IONBF,0);
    setvbuf(stderr,nullptr,_IONBF,0);
    std::string line;
    while(std::getline(std::cin,line)){
        if(line.empty()) continue;
        if(!line.empty()&&line.back()=='\r') line.pop_back();
        auto args=parse_json(line);
        auto it=args.find("_id");
        g_id=(it!=args.end())?it->second:"0";
        auto cmd_it=args.find("cmd");
        if(cmd_it==args.end()){ std::cout<<err("Missing cmd"); continue; }
        const auto& cmd=cmd_it->second;
        std::string resp;
        if      (cmd=="list_processes")  resp=cmd_list_processes();
        else if (cmd=="scan_file")       resp=cmd_scan_file(args);
        else if (cmd=="scan_process")    resp=cmd_scan_process(args);
        else if (cmd=="resolve_chain")   resp=cmd_resolve_chain(args);
        else if (cmd=="batch_scan")      resp=cmd_batch_scan(args);
        else if (cmd=="netvar_dump")      resp=cmd_netvar_dump(args);
        else if (cmd=="export_hpp")      resp=cmd_export_hpp(args);
        else if (cmd=="ping")            resp=ok("\"pong\"");
        else                             resp=err("Unknown: "+cmd);
        std::cout<<resp;
        std::cout.flush();
    }
    return 0;
}

// ── batch_scan ────────────────────────────────────────────────────────────────
// Input JSON:
// { "cmd":"batch_scan", "process":"game.exe",
//   "sigs":"[{\"name\":\"dwHP\",\"pattern\":\"48 8B ? ? ? ?\",\"offset\":3,\"extra\":0,\"relative\":true}]" }
//
// Each sig:
//   name     - label for the result
//   pattern  - IDA-style AOB
//   module   - which module to scan (empty = main module)
//   offset   - byte offset from match start to the displacement field
//   extra    - constant added to final result
//   relative - if true, read 4-byte RIP-relative displacement at 'offset'
//              if false, just return RVA of match + offset

struct SigEntry {
    std::string name;
    std::string pattern;
    std::string module_name;
    int         offset    = 3;
    int         extra     = 0;
    bool        relative  = true;
};

// Minimal JSON array parser for sig entries
static std::vector<SigEntry> parse_sig_array(const std::string& json) {
    std::vector<SigEntry> result;
    if (json.empty()) return result;

    // Find each {...} object
    size_t i = 0;
    while (i < json.size()) {
        // Find opening {
        while (i < json.size() && json[i] != '{') ++i;
        if (i >= json.size()) break;
        size_t obj_start = i;
        // Find matching }
        int depth = 0;
        size_t obj_end = i;
        while (obj_end < json.size()) {
            if (json[obj_end] == '{') ++depth;
            else if (json[obj_end] == '}') { --depth; if (depth == 0) break; }
            ++obj_end;
        }
        if (depth != 0) break;

        // Parse flat fields from this object
        std::string obj = json.substr(obj_start, obj_end - obj_start + 1);

        // Reuse existing flat parser
        // Build a temp map
        std::map<std::string,std::string> fields;
        size_t j = 1;
        auto ws2 = [&](){ while(j<obj.size()&&(obj[j]==' '||obj[j]=='\t'||obj[j]=='\r'||obj[j]=='\n'))++j; };
        auto rstr2 = [&]()->std::string{
            if(j>=obj.size()||obj[j]!='"') return "";
            ++j; std::string s;
            while(j<obj.size()&&obj[j]!='"'){
                if(obj[j]=='\\'&&j+1<obj.size()){++j;s+=obj[j];}
                else s+=obj[j];
                ++j;
            }
            if(j<obj.size())++j;
            return s;
        };
        while(j<obj.size()){
            ws2();
            if(j>=obj.size()||obj[j]=='}') break;
            if(obj[j]=='{'||obj[j]==','){++j;continue;}
            if(obj[j]!='"'){++j;continue;}
            auto key=rstr2(); ws2();
            if(j<obj.size()&&obj[j]==':')++j;
            ws2();
            std::string val;
            if(j<obj.size()&&obj[j]=='"') val=rstr2();
            else{ while(j<obj.size()&&obj[j]!=','&&obj[j]!='}') val+=obj[j++]; }
            if(!key.empty()) fields[key]=val;
        }

        SigEntry e;
        if (fields.count("name"))    e.name        = fields["name"];
        if (fields.count("pattern")) e.pattern     = fields["pattern"];
        if (fields.count("module"))  e.module_name = fields["module"];
        if (fields.count("offset")) {
            try { e.offset = std::stoi(fields["offset"]); } catch(...) {}
        }
        if (fields.count("extra")) {
            try { e.extra = std::stoi(fields["extra"]); } catch(...) {}
        }
        if (fields.count("relative")) {
            e.relative = (fields["relative"] == "true" || fields["relative"] == "1");
        }

        if (!e.name.empty() && !e.pattern.empty())
            result.push_back(std::move(e));

        i = obj_end + 1;
    }
    return result;
}

static std::string cmd_batch_scan(const std::map<std::string,std::string>& a) {
    auto pi   = a.find("process");
    auto si   = a.find("sigs");
    auto fi   = a.find("file");

    bool file_mode = (fi != a.end() && !fi->second.empty());
    bool proc_mode = (pi != a.end() && !pi->second.empty());

    if (!file_mode && !proc_mode)
        return err("Need 'process' or 'file'");
    if (si == a.end() || si->second.empty())
        return err("Missing 'sigs'");

    auto sigs = parse_sig_array(si->second);
    if (sigs.empty())
        return err("No valid signatures parsed");

    std::ostringstream out;
    out << "[";
    bool first_result = true;

    // ── FILE mode ─────────────────────────────────────────────────────────────
    if (file_mode) {
        PEParser parser;
        if (!parser.load(fi->second) || !parser.is_valid())
            return err("Failed to load PE: " + fi->second);

        auto sections = parser.get_sections();

        for (auto& sig : sigs) {
            if (!first_result) out << ",";
            first_result = false;

            out << "{\"name\":" << jstr(sig.name);

            bool found = false;
            try {
                AOBScanner::parse_pattern(sig.pattern); // validate
                for (const auto& sec : sections) {
                    auto data = parser.read_section_data(sec);
                    if (data.empty()) continue;
                    auto hits = AOBScanner::scan_buffer(data.data(), data.size(), sig.pattern);
                    if (hits.empty()) continue;

                    size_t match = hits[0];
                    uintptr_t rva = sec.virtual_address + match;

                    uintptr_t final_offset = rva;
                    if (sig.relative && (int)data.size() >= (int)match + sig.offset + 4) {
                        auto rip = AOBScanner::extract_rip_relative(
                            data.data(), data.size(), match,
                            sig.offset,
                            sig.offset + 4
                        );
                        if (rip.has_value()) {
                            final_offset = (sec.virtual_address + rip.value()) + sig.extra;
                        } else {
                            final_offset = rva + sig.extra;
                        }
                    } else {
                        final_offset = rva + sig.offset + sig.extra;
                    }

                    out << ",\"offset\":" << jstr(to_hex(final_offset))
                        << ",\"rva\":"    << jstr(to_hex(rva))
                        << ",\"section\":" << jstr(sec.name)
                        << ",\"hits\":"   << hits.size()
                        << ",\"ok\":true";
                    found = true;
                    break;
                }
            } catch(...) {
                out << ",\"ok\":false,\"error\":" << jstr("Invalid pattern");
                out << "}";
                continue;
            }

            if (!found) out << ",\"ok\":false,\"error\":" << jstr("Pattern not found");
            out << "}";
        }
    }

    // ── PROCESS mode ──────────────────────────────────────────────────────────
    if (proc_mode) {
        Process proc;
        if (!proc.attach(pi->second))
            return err("Failed to attach: " + pi->second);

        auto main_mod = proc.get_main_module();

        for (auto& sig : sigs) {
            if (!first_result) out << ",";
            first_result = false;

            out << "{\"name\":" << jstr(sig.name);

            // Pick the right module
            std::optional<ModuleInfo> target_mod;
            if (!sig.module_name.empty()) {
                target_mod = proc.get_module(sig.module_name);
            }
            if (!target_mod.has_value()) target_mod = main_mod;

            if (!target_mod.has_value()) {
                out << ",\"ok\":false,\"error\":" << jstr("Module not found") << "}";
                continue;
            }

            bool found = false;
            try {
                AOBScanner::parse_pattern(sig.pattern);

                // Read module memory
                auto data = proc.read_memory_vec(target_mod->base, target_mod->size);
                if (data.empty()) {
                    out << ",\"ok\":false,\"error\":" << jstr("Cannot read module") << "}";
                    continue;
                }

                auto hits = AOBScanner::scan_buffer(data.data(), data.size(), sig.pattern);
                if (!hits.empty()) {
                    size_t match = hits[0];
                    uintptr_t abs_addr = target_mod->base + match;
                    uintptr_t rva = match; // offset within module

                    uintptr_t final_offset = rva;
                    if (sig.relative && (int)data.size() >= (int)match + sig.offset + 4) {
                        auto rip = AOBScanner::extract_rip_relative(
                            data.data(), data.size(), match,
                            sig.offset, sig.offset + 4
                        );
                        if (rip.has_value()) {
                            final_offset = rip.value() + sig.extra;
                        } else {
                            final_offset = rva + sig.extra;
                        }
                    } else {
                        final_offset = rva + sig.offset + sig.extra;
                    }

                    out << ",\"offset\":"  << jstr(to_hex(final_offset))
                        << ",\"rva\":"     << jstr(to_hex(rva))
                        << ",\"absAddr\":" << jstr(to_hex(abs_addr))
                        << ",\"module\":"  << jstr(target_mod->name)
                        << ",\"hits\":"    << hits.size()
                        << ",\"ok\":true";
                    found = true;
                }
            } catch(...) {
                out << ",\"ok\":false,\"error\":" << jstr("Invalid pattern") << "}";
                continue;
            }

            if (!found) out << ",\"ok\":false,\"error\":" << jstr("Not found");
            out << "}";
        }

        proc.detach();
    }

    out << "]";
    return ok(out.str());
}

// ── netvar_dump ───────────────────────────────────────────────────────────────
// Walks the Source engine ClientClass / RecvTable chain in memory and
// dumps every netvar name + offset.
//
// Works for: CS:GO (client.dll), CS2 (client.dll), TF2, L4D2, etc.
//
// RecvTable layout (x64):
//   +0x00  RecvProp*   m_pProps
//   +0x08  int         m_nProps
//   +0x10  <pad>
//   +0x18  char*       m_pNetTableName
//
// RecvProp layout (x64):
//   +0x00  char*       m_pVarName
//   +0x08  int         m_RecvType   (6 = DPT_DataTable → recurse)
//   +0x0C  int         m_Flags
//   +0x28  int         m_Offset
//   +0x38  RecvTable*  m_pDataTable (only if type==6)
//
// ClientClass layout (x64):
//   +0x08  char*       m_pNetworkName
//   +0x10  RecvTable*  m_pRecvTable
//   +0x18  ClientClass* m_pNext

static const int DPT_DataTable = 6;

struct NetVar {
    std::string table;
    std::string name;
    std::string full_name; // table::name
    uintptr_t   offset;
};

// Recursively walk a RecvTable, accumulating base_offset
static void walk_table(
    const Process& proc,
    uintptr_t table_ptr,
    const std::string& table_name,
    uintptr_t base_offset,
    std::vector<NetVar>& out,
    int depth = 0)
{
    if (depth > 6 || !table_ptr) return;

    // Read m_pProps and m_nProps
    auto props_ptr = proc.read<uintptr_t>(table_ptr + 0x00);
    auto n_props   = proc.read<int32_t>  (table_ptr + 0x08);

    if (!props_ptr.has_value() || !n_props.has_value()) return;
    if (*n_props <= 0 || *n_props > 4096) return;

    // Size of RecvProp in x64 is 0x60
    const size_t PROP_SIZE = 0x60;

    for (int i = 0; i < *n_props; ++i) {
        uintptr_t prop = *props_ptr + i * PROP_SIZE;

        auto name_ptr = proc.read<uintptr_t>(prop + 0x00);
        auto type     = proc.read<int32_t>  (prop + 0x08);
        auto offset   = proc.read<int32_t>  (prop + 0x28);

        if (!name_ptr.has_value() || !type.has_value() || !offset.has_value()) continue;

        // Read prop name string (up to 64 bytes)
        std::string prop_name;
        {
            auto buf = proc.read_memory_vec(*name_ptr, 64);
            if (!buf.empty()) {
                for (auto b : buf) {
                    if (!b) break;
                    if (b >= 0x20 && b < 0x7F) prop_name += (char)b;
                }
            }
        }
        if (prop_name.empty()) continue;

        // Skip base class props (they start with "baseclass" or "000")
        if (prop_name == "baseclass" || prop_name.substr(0,3) == "000") {
            // Still recurse into sub-tables
            if (*type == DPT_DataTable) {
                auto sub_table = proc.read<uintptr_t>(prop + 0x38);
                if (sub_table.has_value() && *sub_table) {
                    walk_table(proc, *sub_table, table_name, base_offset + *offset, out, depth+1);
                }
            }
            continue;
        }

        if (*type == DPT_DataTable) {
            // Recurse
            auto sub_table = proc.read<uintptr_t>(prop + 0x38);
            if (sub_table.has_value() && *sub_table) {
                walk_table(proc, *sub_table, table_name, base_offset + *offset, out, depth+1);
            }
        } else {
            // Leaf prop — record it
            NetVar nv;
            nv.table     = table_name;
            nv.name      = prop_name;
            nv.full_name = table_name + "::" + prop_name;
            nv.offset    = base_offset + *offset;
            out.push_back(std::move(nv));
        }
    }
}

static std::string cmd_netvar_dump(const std::map<std::string,std::string>& a) {
    auto pi = a.find("process");
    if (pi == a.end() || pi->second.empty())
        return err("Missing 'process'");

    // Optional filter
    std::string filter;
    auto fi = a.find("filter");
    if (fi != a.end()) filter = fi->second;
    // lowercase filter
    std::string filter_low = filter;
    for (auto& c : filter_low) c = (char)std::tolower((unsigned char)c);

    Process proc;
    if (!proc.attach(pi->second))
        return err("Failed to attach: " + pi->second);

    // Find client.dll
    auto client = proc.get_module("client.dll");
    if (!client.has_value()) {
        proc.detach();
        return err("client.dll not found — is this a Source engine game?");
    }

    // Scan client.dll for the CreateInterface export indirectly:
    // We look for the ClientClass linked list head.
    // Signature for GetAllClasses() in client.dll:
    // The function just returns a global pointer — we scan for a pattern
    // that loads it. Common pattern in CS:GO x64:
    //   48 8B 05 ?? ?? ?? ??   (mov rax, [rip+offset])
    //   C3                     (ret)
    // We'll scan the .text section for this 2-instruction sequence.
    //
    // Fallback: scan the whole module for valid ClientClass chain heads.

    std::vector<NetVar> all_vars;

    // Read entire client.dll
    auto module_data = proc.read_memory_vec(client->base, client->size);
    if (module_data.empty()) {
        proc.detach();
        return err("Cannot read client.dll");
    }

    // Pattern: 48 8B 05 ? ? ? ? C3  (GetAllClasses stub)
    std::vector<uintptr_t> class_list_candidates;
    {
        const std::string pat = "48 8B 05 ? ? ? ? C3";
        auto hits = AOBScanner::scan_buffer(module_data.data(), module_data.size(), pat);
        for (size_t hit : hits) {
            // Extract RIP-relative address
            auto rip_result = AOBScanner::extract_rip_relative(
                module_data.data(), module_data.size(), hit, 3, 7);
            if (rip_result.has_value()) {
                uintptr_t ptr_addr = client->base + rip_result.value();
                auto cc_ptr = proc.read<uintptr_t>(ptr_addr);
                if (cc_ptr.has_value() && *cc_ptr && *cc_ptr > 0x10000) {
                    class_list_candidates.push_back(*cc_ptr);
                }
            }
        }
    }

    // Walk each candidate ClientClass chain
    std::set<uintptr_t> visited_tables;
    int classes_dumped = 0;

    for (uintptr_t head : class_list_candidates) {
        uintptr_t cc = head;
        int safety = 0;

        while (cc && safety++ < 8192) {
            // Read network name pointer (+0x08)
            auto name_ptr  = proc.read<uintptr_t>(cc + 0x08);
            // Read RecvTable pointer (+0x10)
            auto table_ptr = proc.read<uintptr_t>(cc + 0x10);
            // Read next pointer (+0x18)
            auto next_ptr  = proc.read<uintptr_t>(cc + 0x18);

            if (!name_ptr.has_value() || !table_ptr.has_value() || !next_ptr.has_value()) break;
            if (!*name_ptr || !*table_ptr) { cc = next_ptr.value_or(0); continue; }

            // Read class name
            std::string class_name;
            {
                auto buf = proc.read_memory_vec(*name_ptr, 128);
                for (auto b : buf) {
                    if (!b) break;
                    if (b >= 0x20 && b < 0x7F) class_name += (char)b;
                    else break;
                }
            }

            if (!class_name.empty() && class_name[0] == 'C' &&
                visited_tables.find(*table_ptr) == visited_tables.end()) {
                visited_tables.insert(*table_ptr);
                walk_table(proc, *table_ptr, class_name, 0, all_vars);
                ++classes_dumped;
            }

            cc = *next_ptr;
            if (cc == head) break; // loop guard
        }

        if (!all_vars.empty()) break; // found valid chain
    }

    proc.detach();

    if (all_vars.empty())
        return err("No netvars found. Make sure the game is running and fully loaded.");

    // Apply filter
    std::vector<NetVar*> filtered;
    for (auto& v : all_vars) {
        if (filter_low.empty()) {
            filtered.push_back(&v);
        } else {
            std::string full_low = v.full_name;
            for (auto& c : full_low) c = (char)std::tolower((unsigned char)c);
            if (full_low.find(filter_low) != std::string::npos)
                filtered.push_back(&v);
        }
    }

    // Build JSON output
    std::ostringstream o;
    o << "{"
      << "\"total\":" << all_vars.size()
      << ",\"classes\":" << classes_dumped
      << ",\"filtered\":" << filtered.size()
      << ",\"vars\":[";

    bool first = true;
    for (auto* v : filtered) {
        if (!first) o << ",";
        first = false;
        o << "{"
          << "\"table\":"  << jstr(v->table)
          << ",\"name\":"  << jstr(v->name)
          << ",\"full\":"  << jstr(v->full_name)
          << ",\"offset\":" << jstr(to_hex(v->offset))
          << "}";
    }
    o << "]}";

    return ok(o.str());
}
