#include <afxwin.h>

#include "../../shared/logger.hpp"

namespace {
constexpr UINT_PTR kExitTimerId = 1;
constexpr UINT kRunTimeMs = 2 * 60 * 1000;
} // namespace

// Minimal MFC application used as the injection target: it shows a window,
// stays alive for the injection window, then exits on its own.
class CTestUiFrame : public CFrameWnd {
protected:
  afx_msg void OnTimer(UINT_PTR id) {
    if (id == kExitTimerId) {
      LOG_INFO("测试窗口计时结束，准备退出");
      KillTimer(kExitTimerId);
      DestroyWindow();
      PostQuitMessage(0);
    }
  }
  DECLARE_MESSAGE_MAP()
};

BEGIN_MESSAGE_MAP(CTestUiFrame, CFrameWnd)
  ON_WM_TIMER()
END_MESSAGE_MAP()

class CTestUiApp : public CWinApp {
public:
  BOOL InitInstance() override {
    injdrv::log::init_process(L"TARGET");
    LOG_INFO("创建测试窗口，计划运行 {}ms", kRunTimeMs);

    auto *frame = new CTestUiFrame();
    if (frame->Create(nullptr, L"test-ui - injection target") == FALSE) {
      LOG_ERROR("测试窗口创建失败");
      delete frame;
      return FALSE;
    }
    frame->SetTimer(kExitTimerId, kRunTimeMs, nullptr);
    m_pMainWnd = frame;
    frame->ShowWindow(SW_SHOW);
    frame->UpdateWindow();
    LOG_INFO("测试窗口就绪 hwnd=0x{:X}",
              reinterpret_cast<std::uintptr_t>(frame->GetSafeHwnd()));
    return TRUE;
  }

  int ExitInstance() override {
    LOG_INFO("测试宿主退出");
    return CWinApp::ExitInstance();
  }
};

CTestUiApp theApp;