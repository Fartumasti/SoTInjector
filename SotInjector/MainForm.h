#pragma once

#include <iostream>
#include <iomanip>
#include <string>
#include <memory>
#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

#include <windows.h>
#include <psapi.h> //GetModuleFileNameEx
#include <TlHelp32.h>

// Setting DLL access controls
#include <AccCtrl.h>
#include <Aclapi.h>
#include <Sddl.h>

// UWP
#include <atlbase.h>
#include <appmodel.h>

int Main();

namespace SotInjector {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	//using namespace System::Diagnostics;

	bool DLLInjectRemote(uint32_t ProcessID, const std::wstring& DLLpath);
	void SetAccessControl(const std::wstring& ExecutableName, const wchar_t* AccessString);

	/// <summary>
	/// Summary for MainForm
	/// </summary>
	public ref class MainForm : public System::Windows::Forms::Form
	{
	public:
		MainForm(void)
		{
			InitializeComponent();
			//
			//TODO: Add the constructor code here
			//
			Init();
		}
		void Init();

	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~MainForm()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Panel^ panel1;
	protected:
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::Label^ label2;
	private: System::Windows::Forms::TextBox^ textBox1;
	private: System::Windows::Forms::Button^ button1;
	private: System::Windows::Forms::Button^ injectButton;
	private:
		/// <summary>
		/// Required designer variable.
		/// </summary>
		System::ComponentModel::Container ^components;
	private: System::String^ DLLP = "Choose a DLL";
	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::Label^ label4;
	uint32_t ProcID = 0;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		void InitializeComponent(void)
		{
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(MainForm::typeid));
			this->panel1 = (gcnew System::Windows::Forms::Panel());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->injectButton = (gcnew System::Windows::Forms::Button());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->panel1->SuspendLayout();
			this->SuspendLayout();
			// 
			// panel1
			// 
			this->panel1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(30)), static_cast<System::Int32>(static_cast<System::Byte>(30)),
				static_cast<System::Int32>(static_cast<System::Byte>(30)));
			this->panel1->Controls->Add(this->label1);
			this->panel1->Controls->Add(this->label2);
			this->panel1->Dock = System::Windows::Forms::DockStyle::Top;
			this->panel1->Location = System::Drawing::Point(0, 0);
			this->panel1->Name = L"panel1";
			this->panel1->Size = System::Drawing::Size(281, 45);
			this->panel1->TabIndex = 0;
			// 
			// label1
			// 
			this->label1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Right));
			this->label1->AutoSize = true;
			this->label1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(30)), static_cast<System::Int32>(static_cast<System::Byte>(30)),
				static_cast<System::Int32>(static_cast<System::Byte>(30)));
			this->label1->Font = (gcnew System::Drawing::Font(L"Arial", 18));
			this->label1->ForeColor = System::Drawing::Color::White;
			this->label1->Location = System::Drawing::Point(251, 8);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(27, 27);
			this->label1->TabIndex = 1;
			this->label1->Text = L"X";
			this->label1->Click += gcnew System::EventHandler(this, &MainForm::label1_Click);
			// 
			// label2
			// 
			this->label2->Anchor = System::Windows::Forms::AnchorStyles::None;
			this->label2->Font = (gcnew System::Drawing::Font(L"Arial", 14.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label2->ForeColor = System::Drawing::Color::White;
			this->label2->Location = System::Drawing::Point(0, 0);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(281, 45);
			this->label2->TabIndex = 1;
			this->label2->Text = L"Sea of Thieves Injector";
			this->label2->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
			this->label2->MouseDown += gcnew System::Windows::Forms::MouseEventHandler(this, &MainForm::MouseDown_Event);
			this->label2->MouseMove += gcnew System::Windows::Forms::MouseEventHandler(this, &MainForm::MouseMove_Event);
			this->label2->MouseUp += gcnew System::Windows::Forms::MouseEventHandler(this, &MainForm::MouseUp_Event);
			// 
			// textBox1
			// 
			this->textBox1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(30)), static_cast<System::Int32>(static_cast<System::Byte>(30)),
				static_cast<System::Int32>(static_cast<System::Byte>(30)));
			this->textBox1->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;
			this->textBox1->Font = (gcnew System::Drawing::Font(L"Arial", 11));
			this->textBox1->ForeColor = System::Drawing::Color::White;
			this->textBox1->Location = System::Drawing::Point(30, 60);
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(219, 24);
			this->textBox1->TabIndex = 1;
			this->textBox1->Text = L"Choose a DLL";
			this->textBox1->TextChanged += gcnew System::EventHandler(this, &MainForm::textBox1_TextChanged);
			// 
			// button1
			// 
			this->button1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(55)), static_cast<System::Int32>(static_cast<System::Byte>(55)),
				static_cast<System::Int32>(static_cast<System::Byte>(55)));
			this->button1->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->button1->Font = (gcnew System::Drawing::Font(L"Arial", 10.5F));
			this->button1->ForeColor = System::Drawing::Color::White;
			this->button1->Location = System::Drawing::Point(30, 90);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(99, 23);
			this->button1->TabIndex = 2;
			this->button1->Text = L"Select";
			this->button1->UseVisualStyleBackColor = false;
			this->button1->Click += gcnew System::EventHandler(this, &MainForm::button1_Click);
			// 
			// injectButton
			// 
			this->injectButton->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(55)), static_cast<System::Int32>(static_cast<System::Byte>(55)),
				static_cast<System::Int32>(static_cast<System::Byte>(55)));
			this->injectButton->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->injectButton->Font = (gcnew System::Drawing::Font(L"Arial", 10.5F));
			this->injectButton->ForeColor = System::Drawing::Color::White;
			this->injectButton->Location = System::Drawing::Point(150, 90);
			this->injectButton->Name = L"injectButton";
			this->injectButton->Size = System::Drawing::Size(99, 23);
			this->injectButton->TabIndex = 4;
			this->injectButton->Text = L"Inject";
			this->injectButton->UseVisualStyleBackColor = false;
			this->injectButton->Click += gcnew System::EventHandler(this, &MainForm::injectButton_Click);
			// 
			// label3
			// 
			this->label3->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Right));
			this->label3->AutoSize = true;
			this->label3->Font = (gcnew System::Drawing::Font(L"Arial", 11));
			this->label3->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(30)), static_cast<System::Int32>(static_cast<System::Byte>(30)),
				static_cast<System::Int32>(static_cast<System::Byte>(30)));
			this->label3->Location = System::Drawing::Point(234, 131);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(35, 17);
			this->label3->TabIndex = 5;
			this->label3->Text = L"v1.0";
			// 
			// label4
			// 
			this->label4->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Right));
			this->label4->AutoSize = true;
			this->label4->Font = (gcnew System::Drawing::Font(L"Arial", 11));
			this->label4->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(30)), static_cast<System::Int32>(static_cast<System::Byte>(30)),
				static_cast<System::Int32>(static_cast<System::Byte>(30)));
			this->label4->Location = System::Drawing::Point(12, 131);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(135, 17);
			this->label4->TabIndex = 6;
			this->label4->Text = L"unknowncheats.me";
			this->label4->Click += gcnew System::EventHandler(this, &MainForm::label4_Click);
			// 
			// MainForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(281, 157);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->injectButton);
			this->Controls->Add(this->button1);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->panel1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::None;
			this->Icon = (cli::safe_cast<System::Drawing::Icon^>(resources->GetObject(L"$this.Icon")));
			this->Name = L"MainForm";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"SoT Injector";
			this->TopMost = true;
			this->panel1->ResumeLayout(false);
			this->panel1->PerformLayout();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void label1_Click(System::Object^ sender, System::EventArgs^ e) {

		Environment::Exit(0);
	}
	private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e) {

		try
		{
			OpenFileDialog^ OFD = gcnew OpenFileDialog();
			OFD->InitialDirectory = Environment::CurrentDirectory;
			OFD->Title = "Locate DLL";
			OFD->DefaultExt = "dll";
			OFD->Filter = "DLL Files (*.dll)|*.dll";
			OFD->CheckFileExists = true;
			OFD->CheckPathExists = true;
			OFD->ShowDialog();

			if (OFD->FileName != "")
			{
				textBox1->Text = OFD->FileName;
				DLLP = OFD->FileName;
			}
		}
		catch (const std::exception& ex)
		{
			String^ msg = msclr::interop::marshal_as<System::String^>(ex.what());
			MessageBox::Show(msg);
		}
	}

	private: System::Void textBox1_TextChanged(System::Object^ sender, System::EventArgs^ e) {

		// Ensure user can manually change the dll path 
		DLLP = textBox1->Text;
	}


	private: System::Void injectButton_Click(System::Object^ sender, System::EventArgs^ e) {

		System::String^ managed = DLLP;
		std::wstring unmanaged = msclr::interop::marshal_as<std::wstring>(managed);

		SetAccessControl(unmanaged, L"S-1-15-2-1");

		if (!DLLInjectRemote(ProcID, unmanaged))
		{
			MessageBox::Show("Injection Failed !", nullptr, MessageBoxButtons::OK, MessageBoxIcon::Error);
		}
		else
		{
			MessageBox::Show("Injection Succeeded ! Thanks for using me !", "Success", MessageBoxButtons::OK, MessageBoxIcon::Information);
			Environment::Exit(0);
		}
	}
	private: System::Void label4_Click(System::Object^ sender, System::EventArgs^ e) {

		System::Diagnostics::Process::Start("https://www.unknowncheats.me/");
	}

#pragma region Mouse Events

	private:
		bool IsMouseDown = false;
		Point Offset = Point();
	private: System::Void MouseDown_Event(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {

		Offset.X = e->X; Offset.Y = e->Y;
		IsMouseDown = true;
	}
	private: System::Void MouseMove_Event(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {

		if (IsMouseDown)
		{
			Point currentScreenPos = PointToScreen(e->Location);
			Location = Point(currentScreenPos.X - Offset.X, currentScreenPos.Y - Offset.Y);
		}
	}
	private: System::Void MouseUp_Event(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {

		IsMouseDown = false;
	}
#pragma endregion
	
};
}
